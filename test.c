#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>

#define NAME "unstorted bin demo\n"
#define LINE "-------------------------------\n"
// gcc -no-pie -Wl,-rpath,./libc/glibc_2.23_unsafe-unlink/,-dynamic-linker,./libc/glibc_2.23_unsafe-unlink/ld.so.2 -g test.c

void print_banner(void) {
    printf(NAME);
}

void print_leak(void) {
    printf("puts() @ %p\n", &puts);
    char* a = malloc(0x88);
    printf("heap @ %p\n", a-0x10);
    free(a);
}

void print_option(int malloc_count) {
    printf("1) malloc %d/4\n", malloc_count);
    puts("2) target");
    puts("3) quit");
    printf("your option is: ");
}

unsigned long read_num(void) {
    char buf[31];
    unsigned long num;
    read(0, buf, 31);
    num = strtoul(buf, 0, 10);
    return num;
}

void do_malloc(int* malloc_count) {
    if (*malloc_count <= 3){
        printf("malloc size: ");
        char* buf = malloc(read_num());
        if (buf != NULL){
            printf("malloc data: ");
            read(0, buf, malloc_usable_size(buf));
            *malloc_count+=1;
            printf(LINE);
        }
    }
    else{
        printf("Sorry, no more space for you to malloc.\n");
        printf(LINE);
    }
}

void do_target(char* target) {
    printf("The target is :\t%s\n", target);
    printf(LINE);
}

void do_exit(void) {
    exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void* a = malloc(0x88);
    malloc(0x18);

    void* b = malloc(0x88);
    malloc(0x18);
    
    free(a);
    free(b);

    void* c = malloc(0x88);    
    void* d = malloc(0x88);

    free(d);
    
    d = malloc(0x88);
    free(c);
    free(d);

    return 0;
}
