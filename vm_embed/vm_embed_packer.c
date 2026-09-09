/*
 * vm_embed_packer.c
 *
 * Creates a directly runnable protected ELF by appending an authenticated,
 * encrypted payload to an ELF runtime stub. The resulting file is itself the
 * loader: users run it directly and no external loader is required.
 *
 * Build:
 *   cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
 *      -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
 *      -Wl,-z,relro,-z,now vm_embedded_stub.c -o vm_embedded_stub -lcrypto
 *   cc -std=c17 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror \
 *      vm_embed_packer.c -o vm_embed_packer -lcrypto
 *
 * Usage:
 *   VM_PACKER_PASSWORD='long-secret' ./vm_embed_packer \
 *       vm_embedded_stub hello hello.protected
 *   VM_PACKER_PASSWORD='long-secret' ./hello.protected arg1 arg2
 *
 * The input is validated as little-endian x86_64 ELF64. The output is a new
 * ELF; the input is never modified. Static payload inspection is blocked by
 * authenticated encryption, but runtime plaintext can still be observed by a
 * sufficiently privileged debugger.
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC "VMPK2\0\0\0"
#define MAGIC_SIZE 8u
#define SALT_SIZE 16u
#define NONCE_SIZE 12u
#define TAG_SIZE 16u
#define KEY_SIZE 32u
#define PBKDF2_ITERATIONS 600000
#define MAX_PAYLOAD_SIZE (256u * 1024u * 1024u)

struct package_header {
    uint8_t magic[MAGIC_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint64_t payload_size;
    uint8_t tag[TAG_SIZE];
};

static void fail(const char *message)
{
    fprintf(stderr, "vm_embed_packer: %s (%s)\n", message, strerror(errno));
    exit(EXIT_FAILURE);
}

static uint8_t *read_file(const char *path, size_t *size_out)
{
    struct stat st;
    uint8_t *data;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("open input");
    if (fstat(fd, &st) < 0 || st.st_size <= 0 || (uintmax_t)st.st_size > MAX_PAYLOAD_SIZE) {
        close(fd);
        errno = EFBIG;
        fail("input is empty or too large");
    }
    data = malloc((size_t)st.st_size);
    if (data == NULL) fail("allocate input");
    if ((size_t)read(fd, data, (size_t)st.st_size) != (size_t)st.st_size) fail("read input");
    close(fd);
    *size_out = (size_t)st.st_size;
    return data;
}

static int write_full(int fd, const void *buffer, size_t size)
{
    const uint8_t *p = buffer;
    size_t done = 0u;
    while (done < size) {
        ssize_t n = write(fd, p + done, size - done);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static void validate_elf(const uint8_t *data, size_t size)
{
    const Elf64_Ehdr *eh;
    if (size < sizeof(Elf64_Ehdr)) fail("payload is not ELF64");
    eh = (const Elf64_Ehdr *)data;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) ||
        eh->e_machine != EM_X86_64) {
        errno = ENOEXEC;
        fail("payload must be little-endian x86_64 ELF64 ET_EXEC or ET_DYN");
    }
}

static int encrypt_payload(uint8_t *cipher, const uint8_t *plain, size_t size,
                           struct package_header *header, const char *password)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t key[KEY_SIZE];
    int len = 0;
    int total = 0;
    int ok = 0;

    if (PKCS5_PBKDF2_HMAC(password, -1, header->salt, SALT_SIZE,
                          PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key) != 1) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, header->nonce) != 1 ||
        EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)size) != 1) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + total, &len) != 1) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, header->tag) != 1) goto done;
    ok = total == (int)size;
done:
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static void embed(const char *stub_path, const char *payload_path, const char *output_path, const char *password)
{
    size_t stub_size;
    size_t payload_size;
    uint8_t *stub = read_file(stub_path, &stub_size);
    uint8_t *payload = read_file(payload_path, &payload_size);
    uint8_t *cipher = malloc(payload_size);
    struct package_header header = {0};
    int out_fd;

    validate_elf(stub, stub_size);
    validate_elf(payload, payload_size);
    if (cipher == NULL || RAND_bytes(header.salt, SALT_SIZE) != 1 || RAND_bytes(header.nonce, NONCE_SIZE) != 1) fail("create encryption state");
    memcpy(header.magic, MAGIC, MAGIC_SIZE);
    header.payload_size = (uint64_t)payload_size;
    if (encrypt_payload(cipher, payload, payload_size, &header, password) < 0) fail("encrypt payload");

    out_fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (out_fd < 0) fail("create output");
    if (write_full(out_fd, stub, stub_size) < 0 || write_full(out_fd, cipher, payload_size) < 0 || write_full(out_fd, &header, sizeof(header)) < 0) {
        close(out_fd);
        fail("write output");
    }
    if (fchmod(out_fd, 0700) < 0) fail("set output permissions");
    close(out_fd);
    OPENSSL_cleanse(payload, payload_size);
    OPENSSL_cleanse(cipher, payload_size);
    free(stub); free(payload); free(cipher);
    printf("created directly runnable protected ELF: %s\n", output_path);
}

int main(int argc, char **argv)
{
    const char *password = getenv("VM_PACKER_PASSWORD");
    if (argc != 4 || password == NULL || password[0] == '\0') {
        fprintf(stderr, "usage: VM_PACKER_PASSWORD=secret %s runtime_stub input.elf output.elf\n", argv[0]);
        return EXIT_FAILURE;
    }
    embed(argv[1], argv[2], argv[3], password);
    return EXIT_SUCCESS;
}
