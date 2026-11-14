/* Independent, portable C11 interpreter of the x86 arithmetic observed at
 * Rayman2.exe VA 0x4493AD-0x4493DF. No original game binary bytes are stored.
 * Verifies high-bit 32-bit QueryPerformanceCounter seed behavior. */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SALT UINT32_C(0x075BD924)
#define MODULUS INT64_C(2147483647)
#define MULTIPLIER INT64_C(16807)

static int64_t signed_dword(uint32_t n) {
    return n < UINT32_C(0x80000000) ? (int64_t)n : (int64_t)n-INT64_C(4294967296);
}
static int64_t floor_div(int64_t x, int64_t y) {
    int64_t q=x/y, rem=x%y;
    return rem < 0 ? q-1 : q;
}
static uint32_t x86_step(uint32_t current) {
    uint32_t ecx = current ^ SALT;
    /* imul ecx with accumulator 0x834e0b5f, EDX:EAX signed product. */
    const int64_t product=signed_dword(UINT32_C(0x834E0B5F))*signed_dword(ecx);
    uint32_t edx=(uint32_t)(floor_div(product, INT64_C(4294967296)) + signed_dword(ecx));
    /* imul ecx, ecx, 16807: low 32 bits only. */
    ecx=(uint32_t)(signed_dword(ecx)*MULTIPLIER);
    edx=(uint32_t)floor_div(signed_dword(edx),INT64_C(65536)); /* sar edx,16 */
    uint32_t eax=edx>>31;
    edx+=eax;
    eax=(uint32_t)(-signed_dword(edx)); /* neg eax */
    eax<<=31;
    eax-=edx;
    ecx-=eax;
    if(ecx&UINT32_C(0x80000000)) ecx+=UINT32_C(0x7fffffff);
    return ecx;
}
static uint32_t signed_mod_step(uint32_t current) {
    int64_t result=(signed_dword(current^SALT)*MULTIPLIER)%MODULUS;
    if(result<0) result+=MODULUS;
    return (uint32_t)result;
}
int main(void) {
    static const struct {uint32_t initial, first;} golden[] = {
        {UINT32_C(0),UINT32_C(0x1F0CCE42)},
        {UINT32_C(0x12345678),UINT32_C(0x4F2CEC02)},
        {UINT32_C(0x7FFFFFFF),UINT32_C(0x60F331BD)},
        {UINT32_C(0x80000000),UINT32_C(0x1F0C8C9B)},
        {UINT32_C(0x80000001),UINT32_C(0x1F0CCE42)},
        {UINT32_C(0xFFFFFFFF),UINT32_C(0x60F2F016)},
    };
    for(size_t i=0; i<sizeof(golden)/sizeof(golden[0]); ++i) {
        if(x86_step(golden[i].initial)!=golden[i].first ||
           signed_mod_step(golden[i].initial)!=golden[i].first) {
            fprintf(stderr,"golden vector mismatch %zu\n",i); return EXIT_FAILURE;
        }
    }
    uint32_t state=UINT32_C(0x12345678);
    for(int i=0;i<281;++i)state=x86_step(state);
    if(state!=UINT32_C(0x7A833570)) {
        fputs("281-state fallback mismatch\n",stderr);return EXIT_FAILURE;
    }
    uint32_t seed=UINT32_C(0xAC202611);
    unsigned low=0,high=0;
    for(unsigned i=0;i<200000;++i) {
        seed=seed*UINT32_C(1664525)+UINT32_C(1013904223);
        if(x86_step(seed)!=signed_mod_step(seed)) {
            fprintf(stderr,"x86/signed formula mismatch at seed 0x%08" PRIX32 "\n",seed);
            return EXIT_FAILURE;
        }
        if(seed & UINT32_C(0x80000000))++high;else ++low;
    }
    printf("PASS 6 vectors; 281 fallback => 0x%08" PRIX32 "; "
           "200000 full-32-bit inputs: high=%u low=%u\n",state,high,low);
    return EXIT_SUCCESS;
}
