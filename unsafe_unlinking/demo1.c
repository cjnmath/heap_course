#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>

#define NAME "unstorted bin demo\n"
#define LINE "-------------------------------\n"
// gcc -no-pie -Wl,-rpath,../libc/glibc_2.23_unsafe-unlink/,-dynamic-linker,../libc/glibc_2.23_unsafe-unlink/ld.so.2 -g demo1.c -o demo1

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void* a = malloc(0x88);
    malloc(0x18);

    void* b = malloc(0x88);
    malloc(0x18);
    
    free(a);
    free(b);

    return 0;
}
