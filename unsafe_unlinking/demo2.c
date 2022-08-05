#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>

#define NAME "unstorted bin demo2\n"
#define LINE "-------------------------------\n"
// gcc -no-pie -Wl,-rpath,../libc/glibc_2.23_unsafe-unlink/,-dynamic-linker,../libc/glibc_2.23_unsafe-unlink/ld.so.2 -g demo2.c -o demo2

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void* c = malloc(0x88);
    void* d = malloc(0x88);

    free(d);
    
    d = malloc(0x88);
    malloc(0x18);

    free(c);
    free(d);

    return 0;
}
