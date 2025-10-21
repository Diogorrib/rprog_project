#ifndef FEISTEL96_PLAIN_P4
#define FEISTEL96_PLAIN_P4
const bit<128> OFFSET128 = 0x0123456789ABCDEF0FEDCBA987654321;


struct pnrg_state_t {
    bit<128> k1;
    bit<128> k2;
    bit<128> k3;
    bit<128> k4;
    bit<128> k5;
    bit<128> k6;
    bit<128> k7;
    bit<128> k8;
};

bit<128> rng128_forward(inout bit<128> s) {
    bit<128> t = s + OFFSET128;
    t = t ^ (t << 23);
    t = t ^ (t >> 17);
    t = t ^ (t << 31);
    return t;
}

bit<48> F_round(inout bit<48> R, inout bit<128> round_key) {
    bit<80> zero=0;
    bit<128> r128;
    r128[127:48]=0;
    r128[47:0]=R;
    bit<128> rnging1;
    bit<128> rnging2;
    rnging1=r128 ^ round_key;
    bit<128> mixed  = rng128_forward(rnging1);
    rnging1=r128 ^ round_key;
    bit<128> mixed2 = rng128_forward(rnging2);
    bit<128> x = mixed ^ mixed2;
    bit<64> x_lo = (bit<64>) x;
    bit<64> x_hi = (bit<64>) (x >> 64);
    bit<64> reduced = x_lo ^ x_hi;
    return (bit<48>) reduced;
}

void derive_round_keys(bit<128> enc_seed, inout pnrg_state_t meta) {
    bit<128> s = enc_seed;
    s = rng128_forward(s); meta.k1 = s;
    s = rng128_forward(s); meta.k2 = s;
    s = rng128_forward(s); meta.k3 = s;
    s = rng128_forward(s); meta.k4 = s;
    s = rng128_forward(s); meta.k5 = s;
    s = rng128_forward(s); meta.k6 = s;
    s = rng128_forward(s); meta.k7 = s;
    s = rng128_forward(s); meta.k8 = s;
}

void encrypt96(inout bit<48> L, inout bit<48> R, inout pnrg_state_t meta) {
    bit<48> t; 
    bit<48> newR;

    t = F_round(R, meta.k1); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k2); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k3); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k4); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k5); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k6); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k7); newR = L ^ t; L = R; R = newR;
    t = F_round(R, meta.k8); newR = L ^ t; L = R; R = newR;
}

void decrypt96(inout bit<48> L, inout bit<48> R, inout pnrg_state_t meta) {
        bit<48> L_prev;
        bit<48> R_prev;
        bit<48> t;

    // Round 8 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k8);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 7 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k7);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 6 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k6);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 5 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k5);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 4 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k4);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 3 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k3);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 2 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k2);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 1 inverse
    R_prev = L;
    t = F_round(R_prev, meta.k1);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;
}

/*void round(inout bit<48> L_prev, bit<48> R_prev,
    inout bit<48> L, inout bit<48> R, bit<128> k) {
    R_prev = L;
    t = F_round(R_prev, k);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;
}

void decrypt96(inout bit<48> L, inout bit<48> R) {
    bit<48> L_prev;
    bit<48> R_prev;
    bit<48> t;

    round(L_prev, R_prev, L, R, meta.k8);
    round(L_prev, R_prev, L, R, meta.k7);
    round(L_prev, R_prev, L, R, meta.k6);
    round(L_prev, R_prev, L, R, meta.k5);
    round(L_prev, R_prev, L, R, meta.k4);
    round(L_prev, R_prev, L, R, meta.k3);
    round(L_prev, R_prev, L, R, meta.k2);
    round(L_prev, R_prev, L, R, meta.k1);
}*/

void feistel96_encrypt(bit<128> enc_seed, inout bit<96> value){
    bit<48> left;
    bit<48> right;
    pnrg_state_t meta;
    left  = value[95:48];  // upper half (bits 95 down to 48)
    right = value[47:0];   // lower half (bits 47 down to 0)
    derive_round_keys(enc_seed, meta);
    encrypt96(left, right, meta);
    value[95:48] = left;
    value[47:0]  = right;
}
void feistel96_decrypt(bit<128> enc_seed, inout bit<96> value){
    bit<48> left;
    bit<48> right;
    pnrg_state_t meta;
    left  = value[95:48];  // upper half (bits 95 down to 48)
    right = value[47:0];   // lower half (bits 47 down to 0)
    derive_round_keys(enc_seed, meta);
    decrypt96(left, right, meta);
    value[95:48] = left;
    value[47:0]  = right;
}

#endif // FEISTEL96_PLAIN_P4
