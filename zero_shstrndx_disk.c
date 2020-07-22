#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

#include<fcntl.h>
#include<sys/stat.h>
#include<sys/types.h>

int
main(int argc, char *argv[]) {
    FILE *fd, *new_fd;
    struct stat st;

    if (argc != 3) {
        fprintf(stderr, "Usage:%s <infile> <outfile>\n", argv[0]);
        exit(-1);
    }

    if ((fd = fopen(argv[1], "r")) == NULL) {
        perror("fopen");
    }

    if (-1 == stat(argv[1], &st)) {
        perror("stat");
        exit(-1);
    }

    /*
     * Create a buf which can hold the orginal program
     */

    char buf[st.st_size];

    /*
     * Read sizeof(orginal_program) members, each member 1 bytes, from fd
     * to buf
     */

    if (st.st_size != fread(buf, 1, st.st_size, fd)) {
        perror("fread");
        exit(-1);
    }

    /*
     * Check if an ELF file,
     * ELF start with magic number which is
     * 0x7f and folowed by "ELF" string
     */

    if (0x7f != buf[0] && (0 != strcmp(&buf[1], "ELF"))) {
        fprintf(stderr, "Not an ELF file\n");
        exit(-1);
    }

    /*
     * This is the Section header string table index,
     * set it to 0 to avoid debugging
     */

    // printf("%x\n", buf[0x40 - 0x2]);

    buf[0x40 - 0x2] = 0;

    /*
     * Create fd of modified file
     */

    if ((new_fd = fopen(argv[2], "w+")) == NULL) {
        perror("fopen");
        exit(-1);
    }

    /*
     * Write modified data into this fd
     */

    if (st.st_size != fwrite(buf, 1, st.st_size, new_fd)) {
        perror("fwrite");
        exit(-1);
    }

    puts("Patch ELF file successful");

    fclose(fd);
    fclose(new_fd);

    return 0;
}
