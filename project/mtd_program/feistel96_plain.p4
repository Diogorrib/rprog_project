#ifndef FEISTEL96_PLAIN_P4
#define FEISTEL96_PLAIN_P4
const bit<128> OFFSET128 = 0x0123456789ABCDEF0FEDCBA987654321;

bit<128> rng128_forward(inout bit<128> s) {
    bit<128> t = s + OFFSET128;
    t = t ^ (t << 23);
    t = t ^ (t >> 17);
    t = t ^ (t << 31);
    return t;
}

bit<48> F_round(inout bit<48> R, inout bit<128> round_key) {
    bit<80> zero=0;
    bit<128> r128=0;
    r128[127:48]=zero;
    r128[47:0]=R;
    bit<128> rnging1;
    bit<128> rnging2;
    rnging1=r128 ^ round_key;
    bit<128> mixed  = rng128_forward(rnging1);
    rnging2=r128 ^ round_key;
    bit<128> mixed2 = rng128_forward(rnging2);
    bit<128> x = mixed ^ mixed2;
    bit<64> x_lo = (bit<64>) x;
    bit<64> x_hi = (bit<64>) (x >> 64);
    bit<64> reduced = x_lo ^ x_hi;
    return (bit<48>) reduced;
}

void derive_round_keys(inout bit<128> enc_seed, inout bit<128> k1, inout bit<128> k2, inout bit<128> k3, inout bit<128> k4, inout bit<128> k5, inout bit<128> k6, inout bit<128> k7, inout bit<128> k8) {
    bit<128> s = enc_seed;
    s = rng128_forward(s); k1 = s;
    s = rng128_forward(s); k2 = s;
    s = rng128_forward(s); k3 = s;
    s = rng128_forward(s); k4 = s;
    s = rng128_forward(s); k5 = s;
    s = rng128_forward(s); k6 = s;
    s = rng128_forward(s); k7 = s;
    s = rng128_forward(s); k8 = s;
}

void encrypt96(inout bit<48> L, inout bit<48> R, inout bit<128> k1, inout bit<128> k2, inout bit<128> k3, inout bit<128> k4, inout bit<128> k5, inout bit<128> k6, inout bit<128> k7, inout bit<128> k8) {
    bit<48> t; 
    bit<48> newR;

    t = F_round(R, k1); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k2); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k3); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k4); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k5); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k6); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k7); newR = L ^ t; L = R; R = newR;
    t = F_round(R, k8); newR = L ^ t; L = R; R = newR;
}

void decrypt96(inout bit<48> L, inout bit<48> R, inout bit<128> k1, inout bit<128> k2, inout bit<128> k3, inout bit<128> k4, inout bit<128> k5, inout bit<128> k6, inout bit<128> k7, inout bit<128> k8) {
        bit<48> L_prev;
        bit<48> R_prev;
        bit<48> t;

    // Round 8 inverse
    R_prev = L;
    t = F_round(R_prev, k8);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 7 inverse
    R_prev = L;
    t = F_round(R_prev, k7);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 6 inverse
    R_prev = L;
    t = F_round(R_prev, k6);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 5 inverse
    R_prev = L;
    t = F_round(R_prev, k5);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 4 inverse
    R_prev = L;
    t = F_round(R_prev, k4);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 3 inverse
    R_prev = L;
    t = F_round(R_prev, k3);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 2 inverse
    R_prev = L;
    t = F_round(R_prev, k2);
    L_prev = R ^ t;
    L = L_prev; R = R_prev;

    // Round 1 inverse
    R_prev = L;
    t = F_round(R_prev, k1);
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

void decrypt96(inout bit<48> L, inout bit<48> R, inout bit<128> k1, inout bit<128> k2, inout bit<128> k3, inout bit<128> k4, inout bit<128> k5, inout bit<128> k6, inout bit<128> k7, inout bit<128> k8) {
    bit<48> L_prev;
    bit<48> R_prev;
    bit<48> t;

    round(L_prev, R_prev, L, R, k8);
    round(L_prev, R_prev, L, R, k7);
    round(L_prev, R_prev, L, R, k6);
    round(L_prev, R_prev, L, R, k5);
    round(L_prev, R_prev, L, R, k4);
    round(L_prev, R_prev, L, R, k3);
    round(L_prev, R_prev, L, R, k2);
    round(L_prev, R_prev, L, R, k1);
}*/

void feistel96_encrypt(in bit<128> enc_seed, inout bit<96> value){
    bit<48> left;
    bit<48> right;
    bit<128> k1=0;
    bit<128> k2=0;
    bit<128> k3=0;
    bit<128> k4=0;
    bit<128> k5=0;
    bit<128> k6=0;
    bit<128> k7=0;
    bit<128> k8=0;
    bit<128> seed_in;
    seed_in=enc_seed;
    left  = value[95:48];  // upper half (bits 95 down to 48)
    right = value[47:0];   // lower half (bits 47 down to 0)
    derive_round_keys(seed_in, k1, k2, k3, k4, k5, k6, k7, k8);
    encrypt96(left, right, k1, k2, k3, k4, k5, k6, k7, k8);
    value[95:48] = left;
    value[47:0]  = right;
}
void feistel96_decrypt(in bit<128> enc_seed, inout bit<96> value){
    bit<48> left;
    bit<48> right;
    bit<128> k1=0;
    bit<128> k2=0;
    bit<128> k3=0;
    bit<128> k4=0;
    bit<128> k5=0;
    bit<128> k6=0;
    bit<128> k7=0;
    bit<128> k8=0;
    bit<128> seed_in;
    seed_in=enc_seed;
    left  = value[95:48];  // upper half (bits 95 down to 48)
    right = value[47:0];   // lower half (bits 47 down to 0)
    derive_round_keys(seed_in, k1, k2, k3, k4, k5, k6, k7, k8);
    decrypt96(left, right, k1, k2, k3, k4, k5, k6, k7, k8);
    value[95:48] = left;
    value[47:0]  = right;
}

#endif // FEISTEL96_PLAIN_P4
