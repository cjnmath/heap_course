#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>
#include<stdint.h>

#define NAME "unsafe unlinking\n"
#define LINE "-------------------------------\n"
#define MAX_MALLOC 2
#define MIN_SIZE 120
#define MAX_SIZE 1000

// gcc --std=gnu89 -no-pie -Wl,-rpath,../libc/glibc_2.23_unsafe-unlink/,-dynamic-linker,../libc/glibc_2.23_unsafe-unlink/ld.so.2 -g unsafe_unlinking.c -o unsafe_unlinking

void* pointers[MAX_MALLOC];

void print_banner(void) {
    printf(NAME);
    printf(LINE);
}

void print_leak(void) {
    printf("puts() @ %p\n", &puts);
    char* a = malloc(0x88);
    printf("heap @ %p\n", a-0x10);
    free(a);
}

void print_option(int malloc_count) {
    printf("1) malloc %d/%d\n", malloc_count, MAX_MALLOC);
    puts("2) edit");
    puts("3) free");
    puts("4) quit");
    printf("your option is: ");
}

unsigned long read_num(void) {
    char buf[31];
    unsigned long num;
    read(0, buf, 31);
    num = strtoul(buf, 0, 10);
    return num;
}
unsigned long read_num_x(void) {
    char buf[31];
    unsigned long num;
    read(0, buf, 31);
    num = strtoul(buf, 0, 0);
    return num;
}

void do_malloc(int* malloc_count) {
    if (*malloc_count < MAX_MALLOC){
        printf("malloc size(hexadecimal): ");
        unsigned long malloc_size = read_num_x();
        if (malloc_size > MIN_SIZE && malloc_size <= MAX_SIZE){
            char* buf = malloc(malloc_size);
            pointers[*malloc_count] = buf;
            *malloc_count+=1;
        }
        else {
            printf("small chunks only - excluding fast sizes (0x%x < bytes <= 0x%x)\n", MIN_SIZE, MAX_SIZE);
        }
    }
    else{
        printf("Sorry, no more space for you to malloc.\n");
    }
    printf(LINE);
}

void do_free(void) {
    printf("index: ");
    unsigned long index = read_num();
    if (index < MAX_MALLOC) {
        void* pointer = pointers[index];
        free(pointer);
        printf("free %p\n", pointer);
        // pointers[index] = NULL;
        
    }
    printf(LINE);
}

void do_edit()
{
    printf("chunk index: ");
    unsigned long index = read_num();
    if (index < MAX_MALLOC) {
        void* buf = pointers[index];
        if (buf != NULL) {
            printf("input data: ");
            read(0, buf, 3*0x3f0);
            // gets(buf);
        }
        else {
            printf("invalide index\n");
            printf(LINE);
        }
    }
    else{
        printf("invalide index\n");
        printf(LINE);
    }
}

void do_exit(void) {
    printf("exiting...\n");
    printf(LINE);
    exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf(LINE);
    print_banner();
    print_leak();
    printf(LINE);

    int malloc_count = 0;
    print_option(malloc_count);
    unsigned long option_num;
    option_num = read_num();
    while (true) {
        switch (option_num) {
            case 1:
                do_malloc(&malloc_count);
                break;
            case 2:
                do_edit();
                break;
            case 3:
                do_free();
                break;
            case 4:
                do_exit();
                break;
        }   
        print_option(malloc_count); 
        option_num = read_num();
        printf(LINE);
    }
    return 0;
}
