// feistel96_plain.c
// Build: gcc -std=c11 -O2 feistel96_plain.c -o feistel96_plain
// Purpose: reversible 96-bit (12-byte) permutation using 128-bit seed.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

typedef __uint128_t u128;
#define ROUNDS 8   // can be increased for more diffusion

#define OFFSET128  (((u128)0x0123456789ABCDEFULL << 64) | (u128)0x0FEDCBA987654321ULL)

// --- reversible RNG 128-bit step ---
static inline u128 rng128_forward(u128 s) {
    s += OFFSET128;
    s ^= s << 23;
    s ^= s >> 17;
    s ^= s << 31;
    return s;
}

// --- load/store 6-byte block as 64-bit (LE) ---
static inline uint64_t load_u48_le(const unsigned char b[6]) {
    uint64_t v = 0;
    for (int i = 5; i >= 0; --i) {
        v <<= 8;
        v |= (uint64_t)b[i];
    }
    return v;
}
static inline void store_u48_le(uint64_t v, unsigned char out[6]) {
    for (int i = 0; i < 6; ++i) {
        out[i] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
}

// --- Round function F: maps 6 bytes + 128-bit key -> 6 bytes ---
static void F_round(const unsigned char R[6], u128 round_key, unsigned char out[6]) {
    uint64_t r = load_u48_le(R);
    u128 mixed = rng128_forward((u128)r ^ round_key);
    u128 mixed2 = rng128_forward(mixed ^ round_key);
    u128 x = mixed ^ mixed2;
    uint64_t reduced = (uint64_t)(x ^ (x >> 64)); // compress to 64 bits
    store_u48_le(reduced, out); // only use 48 bits
}

// --- derive round keys from 128-bit seed ---
static void derive_round_keys(u128 seed, u128 keys[ROUNDS]) {
    u128 s = seed;
    for (int i = 0; i < ROUNDS; ++i) {
        s = rng128_forward(s);
        keys[i] = s;
    }
}

// --- XOR 6 bytes ---
static inline void xor6(unsigned char out[6], const unsigned char a[6], const unsigned char b[6]) {
    for (int i = 0; i < 6; ++i) out[i] = a[i] ^ b[i];
}

// --- Feistel encrypt: 12 bytes in -> 12 bytes out ---
void encrypt96(const unsigned char in[12], unsigned char out[12], u128 seed) {
    unsigned char L[6], R[6];
    memcpy(L, in, 6);
    memcpy(R, in + 6, 6);

    u128 keys[ROUNDS];
    derive_round_keys(seed, keys);

    unsigned char temp[6];
    for (int r = 0; r < ROUNDS; ++r) {
        F_round(R, keys[r], temp);
        unsigned char newR[6];
        xor6(newR, L, temp);
        memcpy(L, R, 6);
        memcpy(R, newR, 6);
    }

    memcpy(out, L, 6);
    memcpy(out + 6, R, 6);
}

// --- Feistel decrypt ---
void decrypt96(const unsigned char in[12], unsigned char out[12], u128 seed) {
    unsigned char L[6], R[6];
    memcpy(L, in, 6);
    memcpy(R, in + 6, 6);

    u128 keys[ROUNDS];
    derive_round_keys(seed, keys);

    for (int r = ROUNDS - 1; r >= 0; --r) {
        unsigned char R_prev[6];
        memcpy(R_prev, L, 6);
        unsigned char t[6];
        F_round(R_prev, keys[r], t);
        unsigned char L_prev[6];
        xor6(L_prev, R, t);
        memcpy(L, L_prev, 6);
        memcpy(R, R_prev, 6);
    }

    memcpy(out, L, 6);
    memcpy(out + 6, R, 6);
}

// --- helper: print 12-byte buffer as hex ---
static void print_hex12(const unsigned char b[12]) {
    for (int i = 0; i < 12; ++i) printf("%02X", b[i]);
    printf("\n");
}

// --- Demo main ---
int main(void) {
    unsigned char plain[12];
    for (int i = 0; i < 12; ++i) plain[i] = (unsigned char)i;

    u128 seed = (((u128)0x1234567890ABCDEFull) << 64) | (u128)0x0FEDCBA098765432ULL;

    unsigned char cipher[12], recovered[12];

    encrypt96(plain, cipher, seed);
    decrypt96(cipher, recovered, seed);

    printf("Plain   : "); print_hex12(plain);
    printf("Cipher  : "); print_hex12(cipher);
    printf("Recover : "); print_hex12(recovered);

    if (memcmp(plain, recovered, 12) == 0) puts("OK: recovered equals plain");
    else puts("ERROR: mismatch!");

    return 0;
}