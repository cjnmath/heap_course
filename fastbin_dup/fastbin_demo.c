#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>

// gcc -no-pie -Wl,-rpath,../libc/glibc_2.30_no-tcache/,-dynamic-linker,../libc/glibc_2.30_no-tcache/ld.so.2 -g fastbin_demo.c -o fastbin_demo
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    void* a = malloc(1);
    void* b = malloc(1);
    void* c = malloc(1);

    free(a);
    free(b);
    free(c);

    void* d = malloc(1);
    void* e = malloc(1);
    void* f = malloc(1);
    
    return 0;
}
