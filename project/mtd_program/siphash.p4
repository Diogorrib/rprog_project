// SipHash-2-4-128 implementation based on the reference implementation

struct siphash_state_t {
    bit<64> v0;
    bit<64> v1;
    bit<64> v2;
    bit<64> v3;
};

void sip_round(inout siphash_state_t state) {
    state.v0 = state.v0 + state.v1;
    state.v1 = (state.v1 << 13) | (state.v1 >> 51);
    state.v1 = state.v1 ^ state.v0;
    state.v0 = (state.v0 << 32) | (state.v0 >> 32);
    state.v2 = state.v2 + state.v3;
    state.v3 = (state.v3 << 16) | (state.v3 >> 48);
    state.v3 = state.v3 ^ state.v2;
    state.v0 = state.v0 + state.v3;
    state.v3 = (state.v3 << 21) | (state.v3 >> 43);
    state.v3 = state.v3 ^ state.v0;
    state.v2 = state.v2 + state.v1;
    state.v1 = (state.v1 << 17) | (state.v1 >> 47);
    state.v1 = state.v1 ^ state.v2;
    state.v2 = (state.v2 << 32) | (state.v2 >> 32);
}

// constant values defined by the authors of SipHash algorithm
void siphash_initialization(in bit<64> k0, in bit<64> k1, out siphash_state_t state) {
    state.v0 = k0 ^ 0x736f6d6570736575;
    state.v1 = k1 ^ 0x646f72616e646f6d;
    state.v2 = k0 ^ 0x6c7967656e657261;
    state.v3 = k1 ^ 0x7465646279746573;
}

void siphash_compression(in bit<64> m, inout siphash_state_t state) {
    state.v1 = state.v1 ^ 0xee;
    state.v3 = state.v3 ^ m;
    sip_round(state);
    sip_round(state);
    state.v0 = state.v0 ^ m;
}

bit<64> siphash_first_finalization(inout siphash_state_t state) {
    state.v2 = state.v2 ^ 0xee;
    sip_round(state);
    sip_round(state);
    sip_round(state);
    sip_round(state);
    return state.v0 ^ state.v1 ^ state.v2 ^ state.v3;
}

bit<64> siphash_second_finalization(inout siphash_state_t state) {
    state.v1 = state.v1 ^ 0xdd;
    sip_round(state);
    sip_round(state);
    sip_round(state);
    sip_round(state);
    return state.v0 ^ state.v1 ^ state.v2 ^ state.v3;
}

void siphash_2_4(in bit<128> key, in bit<32> ctr, out bit<128> nonce) {
    bit<64> aux = 0;
    siphash_state_t state;
    bit<64> k0 = key[63:0];
    bit<64> k1 = key[127:64];
    bit<64> m = (bit<64>) ctr;
    siphash_initialization(k0, k1, state);
    siphash_compression(m, state);
    aux = siphash_first_finalization(state);
    nonce = (bit<128>) aux;
    aux = siphash_second_finalization(state);
    nonce = (nonce << 64) | (bit<128>) aux;
}
