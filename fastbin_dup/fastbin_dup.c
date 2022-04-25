#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<unistd.h>
#include<malloc.h>

#define NAME "fastbin dup\n"
#define LINE "-------------------------------\n"
#define MAX_MALLOC 7

// gcc -no-pie -Wl,-rpath,../libc/glibc_2.30_no-tcache/,-dynamic-linker,../libc/glibc_2.30_no-tcache/ld.so.2 -g fastbin_dup.c -o fastbin_dup_libc_2.30
// gcc -no-pie -Wl,-rpath,../libc/glibc_2.26_no-tcache/,-dynamic-linker,../libc/glibc_2.26_no-tcache/ld.so.2 -g fastbin_dup.c -o fastbin_dup_libc_2.26
// gcc -no-pie -Wl,-rpath,../libc/glibc_2.23/,-dynamic-linker,../libc/glibc_2.23/ld.so.2 -g fastbin_dup.c -o fastbin_dup_libc_2.23

typedef struct User {
    char username[16];
    char target[16];
} User;
User user = {.target="xxxx"};
void* pointers[MAX_MALLOC];

void print_banner(void) {
    printf(NAME);
    printf(LINE);
}

void print_leak(void) {
    printf("puts @ %p\n", &puts);
    printf(LINE);
}


void get_name(void) {
    printf("Enter your name: ");
    read(0, &user.username, 16);
    printf(LINE);
}

void print_option(int malloc_count) {
    printf("1) malloc %d/%d\n", malloc_count, MAX_MALLOC);
    puts("2) free");
    puts("3) target");
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

void do_malloc(int* malloc_count) {
    if (*malloc_count <= MAX_MALLOC){
        printf("malloc size: ");
        char* buf = malloc(read_num());
        pointers[*malloc_count] = buf;
        *malloc_count+=1;
        if (buf != NULL){
            printf("malloc data: ");
            read(0, buf, malloc_usable_size(buf)+8);
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

void do_target()
{
    printf("The target is: %s\n", user.target);
    printf(LINE);
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
    get_name();

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
                do_free();
                break;
            case 3:
                do_target();
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
