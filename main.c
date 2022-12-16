// Self Modifying code example
// based on https://shanetully.com/2013/12/writing-a-self-mutating-x86_64-c-program/

#include <stdio.h>
#include <windows.h>

void foo(void);
void bar(void);
void foo2(void);
void bar2(void);
void print_function_instructions(void *func_ptr, size_t func_len);
void print_function_shellcode(void *func_ptr, size_t func_len);

// char shellcode[] =
//     "\x48\x31\xd2"                              // xor    %rdx, %rdx
//     "\x48\x31\xc0"                              // xor    %rax, %rax
//     "\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // mov    $0x68732f6e69622f, %rbx
//     "\x53"                                      // push   %rbx
//     "\x48\x89\xe7"                              // mov    %rsp, %rdi
//     "\x50"                                      // push   %rax
//     "\x57"                                      // push   %rdi
//     "\x48\x89\xe6"                              // mov    %rsp, %rsi
//     "\xb0\x3b"                                  // mov    $0x3b, %al
//     "\x0f\x05";                                 // syscall

char shellcode[] =
"\x55"
"\x89"
"\xe5"
"\x83"
"\xec"
"\x28"
"\xc7"
"\x45"
"\xf4"
"\x0"
"\x0"
"\x0"
"\x0"
"\x83"
"\x45"
"\xf4"
"\x1"
"\x8b"
"\x45"
"\xf4"
"\x89"
"\x44"
"\x24"
"\x4"
"\xc7"
"\x4"
"\x24"
"\x83"
"\xb1"
"\x40"
"\x0"
"\xe8"
"\xdd"
"\xfd"
"\xff"
"\xff"
"\x90"
"\x90"
"\x90"
"\x90"
"\x90"
"\x90"
"\x90"
"\x90"
"\x90"
"\xc9"
"\xc3";

int main(void) {
    void *foo_addr = (void*)foo;
    void *bar_addr = (void*)bar;
    void *foo2_addr = (void*)foo2;
    void *bar2_addr = (void*)bar2;
    puts("foo function bytes:\n");
    SIZE_T foo_size = bar_addr - foo_addr;
    SIZE_T foo2_size = bar2_addr - foo2_addr;
    print_function_instructions(foo_addr, foo_size);
    print_function_shellcode(foo_addr, foo_size);

    printf("foo size %x foo2 size %x\n", foo_size, foo2_size);

    puts("Calling Foo...\n");
    foo();

    puts("modifying foo...\n");

// BOOL VirtualProtect(
//   [in]  LPVOID lpAddress,
//   [in]  SIZE_T dwSize,
//   [in]  DWORD  flNewProtect,
//   [out] PDWORD lpflOldProtect
// );

    DWORD old_protections = 0;

    // make foo writeable
    if(!VirtualProtect(
        foo_addr,
        foo_size,
        PAGE_EXECUTE_READWRITE,
        &old_protections
    )) {
        puts("error setting code page to PAGE_EXECUTE_READWRITE.");
        printf("old protections: %x", old_protections);
        return 1;
    }

    printf("old protections: %x\n", old_protections);

    // Change the immediate value in the addl instruction in foo() to 42
    unsigned char *instruction = (unsigned char*)foo_addr + 16;
    *instruction = 0x2A;

    puts("Calling Foo again...\n");
    foo();

    puts("replacing foo code with foo2 code");

    // before replacing code check that foo is larger than foo2
    if(foo_size >= sizeof(shellcode)-1) {
        //memcpy(foo_addr, foo2_addr, foo2_size);
        // write NOP instructions to everything first
        for(unsigned char i=0; i<foo_size-2; i++) {
            unsigned char *instruction = (unsigned char*)foo_addr+i;
            *instruction = 0x90;
        }
        memcpy(foo_addr, shellcode, sizeof(shellcode)-1);
        print_function_instructions(foo_addr, foo_size);
    } else {
        puts("ERROR foo was not large enough for foo2 shellcode");
        return 1;
    }

    puts("Calling Foo the third time...\n");
    foo();


    return 0;
}

void foo(void) {
    int i=0;
    i++;
    printf("i: %d\n", i);
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
}

void bar(void) {}

void foo2(void) {
    int i=0;
    i++;
    printf("x: %d\n", i*2);
}
void bar2(void) {}

void print_function_instructions(void *func_ptr, size_t func_len) {
    for(unsigned char i=0; i<func_len; i++) {
        unsigned char *instruction = (unsigned char*)func_ptr+i;
        printf("%p (%2u): %x\n", func_ptr+i, i, *instruction);
    }
}

void print_function_shellcode(void *func_ptr, size_t func_len) {
    printf("char shellcode[] =\n");
    for(unsigned char i=0; i<func_len; i++) {
        unsigned char *instruction = (unsigned char*)func_ptr+i;
        printf("\"\\x%x\"", *instruction);
        if(i+1<func_len) {
            printf("\n");
        }
    }
    printf(";\n");
}