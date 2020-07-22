#include<elf.h>
#include<stdio.h>
#include<string.h>
#include<stdint.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<sys/fcntl.h>

int
main(int argc, char *argv[]) {
    int fd;

    uint8_t *mem;
    struct stat st;

    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;

    if (argc < 2) {
        printf("Usage:%s <executable>\n", argv[0]);
        printf("Warning:Use it before backup\n");
        exit(0);
    }

    /*
     * Open file withe open syscall
     */

    if ((fd = open(argv[1], O_RDWR)) < 0) {
        perror("open");
        exit(-1);
    }

    /* 
     * Read file status
     */

    if (fstat(fd, &st) < 0) {
        perror("stat");
    }

    /*
     * Map executable into memory
     */

    mem = mmap (NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    ehdr = (Elf32_Ehdr *)mem;
    shdr = (Elf32_Shdr *)&mem[ehdr->e_shoff];

    /*
     * Check magic number
     */

    if (mem[0] != 0x7f && strcmp(&mem[1], "ELF")) {
        fprintf(stderr, "Not an ELF file\n");
        exit(-1);
    }

    /*
     * Check if executable
     */

    if (ehdr->e_type == ET_EXEC) {
        fprintf(stderr, "Not an executable file\n");
        exit(-1);
    }

    /*
     * Set ehdr->e_shstrndx to 0
     */

    ehdr->e_shstrndx = 0;

    /*
     * Sync memory into disk
     */

    if (-1 == msync(mem, st.st_size, MS_ASYNC)) {
        perror("msync");
        exit(-1);
    }

    /*
     * Unmap memory
     */

    if (-1 == munmap(mem, st.st_size)) {
        perror("munmap");
        exit(-1);
    }

    close(fd);
}