// Self Modifying code example
// based on https://shanetully.com/2013/12/writing-a-self-mutating-x86_64-c-program/
// License: MIT

#include <stdio.h>
#include <windows.h>

void foo(void);
void bar(void);
void foo2(void);
void bar2(void);
void print_function_instructions(void *func_ptr, size_t func_len);
void print_function_shellcode(void *func_ptr, size_t func_len);
void xor(char *message, char *key, int messageLength);

// char shellcode[] =
// "\x55" // push ebp
// "\x89\xe5" // mov ebp esp
// "\x83\xec\x28" // sub esp 0x28
// "\xc7\x45\xf4\x1\x0\x0\x0" // mov dword [ebp-0xc {var_10}], 0x1
// "\x8b\x45\xf4"      // move eax, dword [ebp-0xc {var_10}]  {0x0}
// "\x89\x44\x24\x04" //mov dword [esp+0x4 {var_28}], eax  {0x0}
// "\xc7\x04\x24\x8a\xb1\x40\x00" // mov dword [esp {var_2c}], 0x40b18a  {"x: %d\n"}
// "\xe8\xbe\xfd\xff\xff" // call    printf
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\x90" // NOP
// "\xc9" // LEAVE
// "\xc3"; // RETURN

char shellcode[] =
"\x55"
"\x89\xe5"
"\x83\xec\x28"
"\xc7\x45\xf4\x1\x0\x0\x0"
"\x83\x45\xf4"
"\x45"
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
"\x8a"
"\xb1"
"\x40"
"\x0"
"\xe8"
"\xc9"
"\xfd"
"\xff"
"\xff";

// char shellcode[] =


// "\xe8"
// "\xc8"
// "\xfd"
// "\xff"
// "\xff"


// "\xc9"
// "\xc3";

// 00401612 (31): e8
// 00401613 (32): f9
// 00401614 (33): fd
// 00401615 (34): ff
// 00401616 (35): ff

// const char data[55] = 
// {
// 	0x89, 0xe5, 0x83, 0xec, 0x04, 0x6a, 0xf5, 0xe8, 0x3c, 0x27, 0x00, 0x00, 0x89, 0xc3, 0x6a, 0x00,
// 	0x8d, 0x45, 0xfc, 0x50, 0x6a, 0x0d,
//     //0x68, 0x39, 0x14, 0x40, 0x00, // 0x401439 {var_18}
//     0x68, 0x8b, 0x16, 0x40, 0x00, // push hello world 0040168b 
    
//     0x53, // ebx {var_1c}
//     0xe8, 0xe7, 0x26, 0x00, 0x00, // call WriteFile
//     0x6a, 0x00, // push 0x0


//     0xe8, 0x68, 0x27, 0x00, 0x00, // call    ExitProcess
    
//     0xf4, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, //hello world 0040168b 
// 	0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0a, 0x66
// };

char xor_shellcode[] =
"\x26"
"\xec"
"\x86"
"\xf1"
"\x9f"
"\x4d"
"\xa4"
"\x37"
"\x87"
"\x65"
"\x63"
"\x72"
"\x73"
"\xe6"
"\x26"
"\x86"
"\x59"
"\xee"
"\x26"
"\x86"
"\xfa"
"\x21"
"\x47"
"\x76"
"\xb4"
"\x61"
"\x47"
"\x4d"
"\xc2"
"\x25"
"\x63"
"\x9a"
"\x6c"
"\x9b"
"\x9c"
"\x8d"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xf5"
"\xf3"
"\xe2"
"\xe3"
"\xac"
"\xa0";

int main(void) {
    char key[11] = "secretpenis";
    void *foo_addr = (void*)foo;
    void *bar_addr = (void*)bar;
    // void *foo2_addr = (void*)foo2;
    // void *bar2_addr = (void*)bar2;
    puts("foo function bytes:\n");
    SIZE_T foo_size = bar_addr - foo_addr;
    // SIZE_T foo2_size = bar2_addr - foo2_addr;
    print_function_instructions(foo_addr, foo_size);
    print_function_shellcode(foo_addr, foo_size);

    printf("foo size %x\n", foo_size);
    // printf("foo size %x foo2 size %x\n", foo_size, foo2_size);

    puts("Calling Foo...\n");
    foo();
    puts("modifying foo...\n");


    DWORD old_protections = 0;

    // make foo writeable
    if(!VirtualProtect(
        foo_addr,               //   [in]  LPVOID lpAddress,
        foo_size,               //   [in]  SIZE_T dwSize,
        PAGE_EXECUTE_READWRITE, //   [in]  DWORD  flNewProtect,
        &old_protections        //   [out] PDWORD lpflOldProtect
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
    if(foo_size >= sizeof(xor_shellcode)-1) {
        // memcpy(foo_addr, foo2_addr, foo2_size);
        // write NOP instructions to everything first
        // for(unsigned char i=0; i<foo_size-2; i++) {
        //     unsigned char *instruction = (unsigned char*)foo_addr+i;
        //     *instruction = 0x90;
        // }
        memcpy(foo_addr, xor_shellcode, sizeof(xor_shellcode)-1);
        print_function_instructions(foo_addr, foo_size);
    } else {
        puts("ERROR foo was not large enough for foo2 shellcode");
        return 1;
    }

    xor(foo_addr,key,foo_size);
    //print_function_shellcode(foo_addr, foo_size);

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
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
    __asm__ ("nop");
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
    int i=1;
    i+=69;
    printf("x: %d\n", i);
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

void xor(char *message, char *key, int messageLength)
{
    for (int i = 0; i < messageLength; i++) {
        message[i] ^= key[i % sizeof(key)];
    }
}