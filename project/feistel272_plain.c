// feistel272_plain.c
// Build: gcc -std=c11 -O2 feistel272_plain.c -o feistel272_plain
// Purpose: reversible 272-bit permutation (34 bytes) using 128-bit seed,
//          no external libraries required.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

typedef __uint128_t u128;
#define ROUNDS 8   // increase for more diffusion (8,12,16,...)

// A constant offset mixed inside the small reversible RNG
#define OFFSET128  (((u128)0x0123456789ABCDEFULL << 64) | (u128)0x0FEDCBA987654321ULL)

// --- small reversible 128-bit step (deterministic, unsigned wrap) ---
static inline u128 rng128_forward(u128 s) {
    s += OFFSET128;
    s ^= s << 23;
    s ^= s >> 17;
    s ^= s << 31;
    return s;
}

// --- load/store 16 bytes <-> u128 (little-endian) ---
static inline u128 load_u128_le(const unsigned char b[16]) {
    u128 v = 0;
    for (int i = 15; i >= 0; --i) {
        v <<= 8;
        v |= (u128)b[i];
    }
    return v;
}
static inline void store_u128_le(u128 v, unsigned char out[16]) {
    for (int i = 0; i < 16; ++i) {
        out[i] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
}

// --- Round function F: maps 17-byte R and 128-bit key -> 17-byte output ---
// Deterministic mixing using the reversible rng; output depends on R and key
static void F_round(const unsigned char R[17], u128 round_key, unsigned char out[17]) {
    u128 r0 = load_u128_le(R);     // bytes 0..15 -> u128
    unsigned char r16 = R[16];     // last byte

    // Mix r0 with key through the 128-bit reversible function
    u128 t1 = rng128_forward(r0 ^ round_key);
    u128 t2 = rng128_forward(t1 ^ round_key);

    // produce 16 bytes from t1 ^ t2
    u128 mix = t1 ^ t2;
    store_u128_le(mix, out);       // out[0..15]

    // last byte depends on r16 and both t1,t2 so it mixes everything
    unsigned char last = (unsigned char)((t2) & 0xFF) ^ (unsigned char)((t1 >> 8) & 0xFF) ^ r16;
    out[16] = last;
}

// --- derive round keys from 128-bit seed (chain rng) ---
static void derive_round_keys(u128 seed, u128 keys[ROUNDS]) {
    u128 s = seed;
    for (int i = 0; i < ROUNDS; ++i) {
        s = rng128_forward(s);
        keys[i] = s;
    }
}

// --- XOR 17 bytes ---
static inline void xor17(unsigned char out[17], const unsigned char a[17], const unsigned char b[17]) {
    for (int i = 0; i < 17; ++i) out[i] = a[i] ^ b[i];
}

// --- Feistel encrypt (34 bytes in -> 34 bytes out) ---
void encrypt272(const unsigned char in[34], unsigned char out[34], u128 seed) {
    unsigned char L[17], R[17];
    memcpy(L, in, 17);
    memcpy(R, in + 17, 17);

    u128 keys[ROUNDS];
    derive_round_keys(seed, keys);

    unsigned char temp[17];
    for (int r = 0; r < ROUNDS; ++r) {
        F_round(R, keys[r], temp);        // temp = F(R, K_r)
        unsigned char newR[17];
        xor17(newR, L, temp);             // newR = L XOR F(R, K_r)
        // advance: L <- R ; R <- newR
        memcpy(L, R, 17);
        memcpy(R, newR, 17);
    }

    // write out L || R
    memcpy(out, L, 17);
    memcpy(out + 17, R, 17);
}

// --- Feistel decrypt (inverse) ---
void decrypt272(const unsigned char in[34], unsigned char out[34], u128 seed) {
    unsigned char L[17], R[17];
    memcpy(L, in, 17);
    memcpy(R, in + 17, 17);

    u128 keys[ROUNDS];
    derive_round_keys(seed, keys);

    // inverse rounds
    for (int r = ROUNDS - 1; r >= 0; --r) {
        unsigned char R_prev[17];
        memcpy(R_prev, L, 17);           // R_prev = L
        unsigned char t[17];
        F_round(R_prev, keys[r], t);     // t = F(R_prev, K_r)
        unsigned char L_prev[17];
        xor17(L_prev, R, t);             // L_prev = R XOR F(R_prev, K_r)
        // set for next step
        memcpy(L, L_prev, 17);
        memcpy(R, R_prev, 17);
    }

    memcpy(out, L, 17);
    memcpy(out + 17, R, 17);
}

// --- helper: print 34-byte buffer as hex ---
static void print_hex34(const unsigned char b[34]) {
    for (int i = 0; i < 34; ++i) printf("%02X", b[i]);
    printf("\n");
}

// --- Demo main ---
int main(void) {
    unsigned char plain[34];
    for (int i = 0; i < 34; ++i) plain[i] = (unsigned char)i; // example plaintext

    // example 128-bit seed (two 64-bit words)
    u128 seed = (((u128)0x1234567890ABCDEFull) << 64) | (u128)0x0FEDCBA098765432ULL;

    unsigned char cipher[34], recovered[34];

    encrypt272(plain, cipher, seed);
    decrypt272(cipher, recovered, seed);

    printf("Plain   : "); print_hex34(plain);
    printf("Cipher  : "); print_hex34(cipher);
    printf("Recover : "); print_hex34(recovered);

    if (memcmp(plain, recovered, 34) == 0) puts("OK: recovered equals plain");
    else puts("ERROR: mismatch!");

    return 0;
}