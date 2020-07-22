#include<stdio.h>
#include<unistd.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

#include<elf.h>
#include<sys/stat.h>
#include<sys/fcntl.h>
#include<sys/mman.h>

int
main(int argc, char *argv[]) {

    if (2 != argc) {
        fprintf(stderr, "Usage:%s <executable>\n", argv[0]);
        puts("Warning:Use it before backup");
        exit(-1);
    }

    int fd, new_fd;
    struct stat st;
    uint8_t *mem;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;

    if (-1 == (fd = open(argv[1], O_RDWR))) {
        perror("open");
        exit(-1);
    }

    /*
     * Get file status
     */

    if (-1 == fstat(fd, &st)) {
        perror("fstat");
        exit(-1);
    }

    /*
     * Map program into memory, I will use msync, so I use PRO_READ and PRO_WRITE flag here
     */

    mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (MAP_FAILED == mem) {
        perror("mmap");
        exit(-1);
    }

    /*
     * Locate ehdr and shdr
     */

    ehdr = (Elf64_Ehdr *)mem;
    shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];

    /*
     * Check if ELF file
     */

    if (0x7f != mem[0] && strcmp(&mem[1], "ELF")) {
        fprintf(stderr, "Not an ELF file\n");
        exit(-1);
    }

    int shdr_size;

    /*
     * Get section header size, so that I can occupy them by 0, to avoid debugging
     */

    shdr_size = ehdr->e_shentsize;
    memset(shdr, 0, shdr_size);

    /*
     * Sync memory to disk
     */

    if (-1 == msync(mem, st.st_size, MS_SYNC)) {
        perror("msync");
        exit(-1);
    }

    puts("Modify file successfully");

    /*
     * Do some end stuff
     */

    if (-1 == close(fd)) {
        perror("close");
        exit(-1);
    }

    if (-1 == munmap(mem, st.st_size)) {
        perror("munmap");
        exit(-1);
    }
}