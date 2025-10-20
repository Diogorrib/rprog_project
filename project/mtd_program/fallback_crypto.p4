/*************************************************************************
*********************** D E F I N I T I O N S  ***************************
*************************************************************************/

struct halfsiphash_state_t {
    bit<32> v0;
    bit<32> v1;
    bit<32> v2;
    bit<32> v3;
};


/*************************************************************************
*********************** F A L L B A C K  P N R G  ************************
*************************************************************************/

void halfsiphash_round(inout halfsiphash_state_t state) {
    state.v0 = state.v0 + state.v1;
    state.v1 = (state.v1 << 5) | (state.v1 >> 27);
    state.v1 = state.v1 ^ state.v0;
    state.v0 = (state.v0 << 16) | (state.v0 >> 16);

    state.v2 = state.v2 + state.v3;
    state.v3 = (state.v3 << 8) | (state.v3 >> 24);
    state.v3 = state.v3 ^ state.v2;

    state.v0 = state.v0 + state.v3;
    state.v3 = (state.v3 << 7) | (state.v3 >> 25);
    state.v3 = state.v3 ^ state.v0;

    state.v2 = state.v2 + state.v1;
    state.v1 = (state.v1 << 13) | (state.v1 >> 19);
    state.v1 = state.v1 ^ state.v2;
}

bit<128> generate_nonce(in bit<128> key, in bit<32> ctr) {
    halfsiphash_state_t state;
    bit<128> nonce;
    bit<32> aux;
    bit<32> base = 0;
    bit<32> max = (bit<32>)0xFFFFFFFF;

    state.v0 = key[31:0] ^ ctr;
    state.v1 = key[63:32] + ctr;
    state.v2 = key[95:64] ^ (~ctr);
    state.v3 = key[127:96] + (~ctr);

    halfsiphash_round(state);

    hash(aux, HashAlgorithm.crc32, base, { state.v0 }, max);
    nonce = (bit<128>)aux;
    hash(aux, HashAlgorithm.crc32, base, { state.v1 }, max);
    nonce = (nonce << 32) | (bit<128>)aux;
    hash(aux, HashAlgorithm.crc32, base, { state.v2 }, max);
    nonce = (nonce << 32) | (bit<128>)aux;
    hash(aux, HashAlgorithm.crc32, base, { state.v3 }, max);
    nonce = (nonce << 32) | (bit<128>)aux;

    return nonce;
}
