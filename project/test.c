#include <stdio.h>
#include <stdint.h>

// --- Constants ---
#define OFFSET16  12345u
#define OFFSET32  987654321u

// --- 16-bit reversible RNG ---
uint16_t rng16_forward(uint16_t input) {
    uint16_t s = input + OFFSET16;
    s ^= s << 7;
    s ^= s >> 9;
    s ^= s << 8;
    return s;
}

uint16_t rng16_inverse(uint16_t output) {
    uint16_t s = output;
    // reverse order
    s ^= s << 8;
    /*s ^= s << 16;*/
    s ^= s >> 9;
    s ^= s << 7;
    s ^= s << 14;
    return s - OFFSET16;
}

// --- 32-bit reversible RNG ---
uint32_t rng32_forward(uint32_t input) {
    uint32_t s = input + OFFSET32;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

uint32_t rng32_inverse(uint32_t output) {
    uint32_t s = output;
    s ^= s << 5;  s ^= s << 10;  s ^= s << 20;
    s ^= s >> 17;
    s ^= s << 13; s ^= s << 26;
    return s - OFFSET32;
}

// --- Example usage ---
int main(void) {
    uint8_t in8_1=232;
    uint8_t in8_2=224;
    uint16_t in16 = 54321;
    uint32_t in32 = 123456789u;

    uint64_t num = 0x123456789ABC;  // 48-bit number
    //printf("0x%012X 0x%012X\n", in8_1, in8_2);
    uint16_t in16_combined= ((uint16_t)in8_1 << 8) | in8_2;
    //printf("0x%012X\n", in16_combined);
    uint32_t in32_l  = (num >> 16) & 0xFFFFFFFF;  // upper 32 bits
    uint16_t in16_r = num & 0xFFFF;              // lower 16 bits

    /*printf("Left (32 bits):  0x%08X\n", in32_l);
    printf("Right (16 bits): 0x%04X\n", in16_r);*/

    uint16_t r16_combined = rng16_forward(in16_combined);
    uint16_t r16 = rng16_forward(in16_r);
    uint32_t r32 = rng32_forward(in32_l);
    
    uint16_t  inv16_combined = rng16_inverse(r16_combined);
    uint16_t  inv16 = rng16_inverse(r16);
    uint32_t  inv32 = rng32_inverse(r32);
    
    uint8_t inv8_1  = (inv16_combined >> 8) & 0xFF;  // upper 8 bits
    uint8_t inv8_2 = inv16_combined & 0xFF;              // lower 8 bits
    uint64_t recombined = ((uint64_t)inv32 << 16) | inv16;
    if(inv8_1==in8_1)
        printf("correct 8 left\n");
    if(inv8_2==in8_2)
        printf("correct 8 right\n");
    if(recombined==num)
        printf("Recombined: 0x%012lX\n", recombined);

    return 0;
}
