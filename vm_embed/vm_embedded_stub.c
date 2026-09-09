/* Runtime embedded in the final protected ELF. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC "VMPK2\0\0\0"
#define MAGIC_SIZE 8u
#define SALT_SIZE 16u
#define NONCE_SIZE 12u
#define TAG_SIZE 16u
#define KEY_SIZE 32u
#define MAX_PAYLOAD_SIZE (256u * 1024u * 1024u)
#define PBKDF2_ITERATIONS 600000
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001u
#endif

struct package_header {
    uint8_t magic[MAGIC_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint64_t payload_size;
    uint8_t tag[TAG_SIZE];
};

extern char **environ;

static void fail(const char *message) { fprintf(stderr, "embedded-vm: %s\n", message); exit(EXIT_FAILURE); }

static int read_full(int fd, void *buf, size_t n) {
    uint8_t *p = buf; size_t done = 0u;
    while (done < n) { ssize_t r = read(fd, p + done, n - done); if (r == 0) return -1; if (r < 0) { if (errno == EINTR) continue; return -1; } done += (size_t)r; }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf; size_t done = 0u;
    while (done < n) { ssize_t r = write(fd, p + done, n - done); if (r == 0) return -1; if (r < 0) { if (errno == EINTR) continue; return -1; } done += (size_t)r; }
    return 0;
}

static void validate_elf(const uint8_t *p, size_t n) {
    const Elf64_Ehdr *e;
    if (n < sizeof(Elf64_Ehdr)) fail("payload is not ELF64");
    e = (const Elf64_Ehdr *)p;
    if (memcmp(e->e_ident, ELFMAG, SELFMAG) != 0 || e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_ident[EI_DATA] != ELFDATA2LSB || (e->e_type != ET_EXEC && e->e_type != ET_DYN) || e->e_machine != EM_X86_64) fail("unsupported payload ELF");
}

static int decrypt(uint8_t *out, const uint8_t *in, size_t n, const struct package_header *h, const char *password) {
    uint8_t key[KEY_SIZE]; EVP_CIPHER_CTX *ctx = NULL; int len = 0; int total = 0; int ok = 0;
    if (PKCS5_PBKDF2_HMAC(password, -1, h->salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key) != 1) goto done;
    ctx = EVP_CIPHER_CTX_new(); if (ctx == NULL) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) != 1 || EVP_DecryptInit_ex(ctx, NULL, NULL, key, h->nonce) != 1 || EVP_DecryptUpdate(ctx, out, &len, in, (int)n) != 1) goto done;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)h->tag) != 1 || EVP_DecryptFinal_ex(ctx, out + total, &len) != 1) goto done;
    total += len; ok = total == (int)n;
done:
    OPENSSL_cleanse(key, sizeof(key)); EVP_CIPHER_CTX_free(ctx); return ok ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *password = getenv("VM_PACKER_PASSWORD");
    const char *self = "/proc/self/exe";
    struct stat st; struct package_header h; uint8_t *cipher; uint8_t *plain; int fd; int memfd;
    char **child_argv;
    (void)argc;
    if (password == NULL || password[0] == '\0') fail("VM_PACKER_PASSWORD is not set");
    fd = open(self, O_RDONLY | O_CLOEXEC); if (fd < 0 || fstat(fd, &st) < 0) fail("cannot open protected ELF");
    if ((uintmax_t)st.st_size < sizeof(h)) fail("protected ELF has no package");
    if (lseek(fd, st.st_size - (off_t)sizeof(h), SEEK_SET) < 0 || read_full(fd, &h, sizeof(h)) < 0 || memcmp(h.magic, MAGIC, MAGIC_SIZE) != 0 || h.payload_size == 0u || h.payload_size > MAX_PAYLOAD_SIZE || (uintmax_t)h.payload_size + sizeof(h) > (uintmax_t)st.st_size) fail("invalid embedded package");
    if (lseek(fd, st.st_size - (off_t)sizeof(h) - (off_t)h.payload_size, SEEK_SET) < 0) fail("cannot seek payload");
    cipher = malloc((size_t)h.payload_size); plain = malloc((size_t)h.payload_size); if (cipher == NULL || plain == NULL) fail("out of memory");
    if (read_full(fd, cipher, (size_t)h.payload_size) < 0 || decrypt(plain, cipher, (size_t)h.payload_size, &h, password) < 0) fail("payload authentication failed");
    validate_elf(plain, (size_t)h.payload_size);
    memfd = memfd_create("embedded-vm-payload", MFD_CLOEXEC); if (memfd < 0 || write_full(memfd, plain, (size_t)h.payload_size) < 0 || fchmod(memfd, 0500) < 0) fail("cannot create anonymous payload");
    child_argv = argc > 0 ? argv : NULL;
    fexecve(memfd, child_argv, environ);
    fail("fexecve failed");
}
