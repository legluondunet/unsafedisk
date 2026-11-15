#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

static void *strict_map(uintptr_t address, size_t size, int prot) {
    void *out = mmap((void*)address, size, prot,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (out != (void *)address) {
        fprintf(stderr, "MAP_UNAVAILABLE at %p errno=%d\n", (void*)address, errno);
        exit(42);
    }
    return out;
}
int main(void) {
    strict_map(0x00400000, 0xA0000, PROT_READ | PROT_EXEC);
    strict_map(0x004A1000, 0x1000, PROT_READ | PROT_WRITE);
    strict_map(0x00510000, 0x2000, PROT_READ | PROT_WRITE);
    if (prctl(PR_SET_NAME, "Rayman2.exe", 0, 0, 0) != 0) return 43;
    *(volatile uint32_t *)0x005113EC = 0x1234;
    *(volatile uint32_t *)0x00510BF4 = 1;
    *(volatile uint32_t *)0x004A1400 = 0;
    *(volatile uint32_t *)0x004A1468 = 0xCAFE;
    *(volatile uint32_t *)0x004A1498 = 0;
    puts("READY"); fflush(stdout);
    int key;
    while ((key = getchar()) != EOF) {
        if (key == 'q') break;
        if (key == 'x') {
            if (mprotect((void*)0x00511000, 4096, PROT_READ | PROT_EXEC) != 0) {
                puts("PERM_CHANGE_DENIED");
            } else puts("EXEC_CHANGED");
            fflush(stdout);
        }
        if (key == 'w') {
            if (mprotect((void*)0x00511000, 4096, PROT_READ | PROT_WRITE) != 0) {
                puts("PERM_CHANGE_DENIED");
            } else puts("WRITE_CHANGED");
            fflush(stdout);
        }
    }
    return 0;
}
