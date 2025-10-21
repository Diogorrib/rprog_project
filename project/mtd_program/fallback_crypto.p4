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

/*************************************************************************
*********************** F A L L B A C K  P R F  **************************
*************************************************************************/

// Feistel network for 96-bit input/output ///////////////////////////////

void feistel_split_96(out bit<48> L, out bit<48> R, in bit<96> input) {
    L = input[95:48];
    R = input[47:0];
}

void feistel_combine_96(in bit<48> L, in bit<48> R, out bit<96> output) {
    output = (bit<96>)L;
    output = (output << 48) | (bit<96>)R;
}

void feistel_get_round_key_96(in bit<128> master_key, in bit<8> round_index, out bit<48> round_key) {
    bit<128> s = master_key;

    s = s + (bit<128>)round_index;

    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 37);

    s = s ^ (s << 7);
    s = s ^ (s >> 11);
    s = s ^ (s << 23);

    round_key = s[127:80];
}

bit<48> feistel_F_round_96(in bit<48> R, in bit<48> round_key) {
    bit<48> rotated = (R << 5) | (R >> 43);
    return rotated ^ round_key;
}

void feistel_round_96(inout bit<48> L, inout bit<48> R, in bit<48> round_key) {
    bit<48> F_out = feistel_F_round_96(R, round_key);
    bit<48> R_new = L ^ F_out;
    L = R;
    R = R_new;
}

void feistel_encrypt_96(inout bit<96> fields, in bit<128> master_key) {
    bit<48> L;
    bit<48> R;
    bit<48> round_key;
    bit<8> i = 0;

    feistel_split_96(L, R, fields);

    feistel_get_round_key_96(master_key, i, round_key);
    feistel_round_96(L, R, round_key);
    i = i + 1;

    feistel_get_round_key_96(master_key, i, round_key);
    feistel_round_96(L, R, round_key);

    feistel_combine_96(L, R, fields);
}

void feistel_decrypt_96(inout bit<96> fields, in bit<128> master_key) {
    bit<48> L;
    bit<48> R;
    bit<48> round_key;
    bit<8> i = 1;

    feistel_split_96(L, R, fields);

    feistel_get_round_key_96(master_key, i, round_key);
    feistel_round_96(R, L, round_key);
    i = i - 1;

    feistel_get_round_key_96(master_key, i, round_key);
    feistel_round_96(R, L, round_key);

    feistel_combine_96(L, R, fields);
}

// Feistel network for 84-bit input/output ///////////////////////////////

void feistel_split_84(out bit<42> L, out bit<42> R, in bit<84> input) {
    L = input[83:42];
    R = input[41:0];
}

void feistel_combine_84(in bit<42> L, in bit<42> R, out bit<84> output) {
    output = (bit<84>)L;
    output = (output << 42) | (bit<84>)R;
}

void feistel_get_round_key_84(in bit<128> master_key, in bit<8> round_index, out bit<42> round_key) {
    bit<128> s = master_key;

    s = s + (bit<128>)round_index;

    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 37);

    s = s ^ (s << 7);
    s = s ^ (s >> 11);
    s = s ^ (s << 23);

    round_key = s[79:38];
}

bit<42> feistel_F_round_84(in bit<42> R, in bit<42> round_key) {
    bit<42> rotated = (R << 5) | (R >> 37);
    return rotated ^ round_key;
}

void feistel_round_84(inout bit<42> L, inout bit<42> R, in bit<42> round_key) {
    bit<42> F_out = feistel_F_round_84(R, round_key);
    bit<42> R_new = L ^ F_out;
    L = R;
    R = R_new;
}

void feistel_encrypt_84(inout bit<84> fields, in bit<128> master_key) {
    bit<42> L;
    bit<42> R;
    bit<42> round_key;
    bit<8> i = 0;

    feistel_split_84(L, R, fields);

    feistel_get_round_key_84(master_key, i, round_key);
    feistel_round_84(L, R, round_key);
    i = i + 1;

    feistel_get_round_key_84(master_key, i, round_key);
    feistel_round_84(L, R, round_key);

    feistel_combine_84(L, R, fields);
}

void feistel_decrypt_84(inout bit<84> fields, in bit<128> master_key) {
    bit<42> L;
    bit<42> R;
    bit<42> round_key;
    bit<8> i = 1;

    feistel_split_84(L, R, fields);

    feistel_get_round_key_84(master_key, i, round_key);
    feistel_round_84(R, L, round_key);
    i = i - 1;

    feistel_get_round_key_84(master_key, i, round_key);
    feistel_round_84(R, L, round_key);

    feistel_combine_84(L, R, fields);
}

// Feistel network for 48-bit input/output ///////////////////////////////

void feistel_split_48(out bit<24> L, out bit<24> R, in bit<48> input) {
    L = input[47:24];
    R = input[23:0];
}

void feistel_combine_48(in bit<24> L, in bit<24> R, out bit<48> output) {
    output = (bit<48>)L;
    output = (output << 24) | (bit<48>)R;
}

void feistel_get_round_key_48(in bit<128> master_key, in bit<8> round_index, out bit<24> round_key) {
    bit<128> s = master_key;

    s = s + (bit<128>)round_index;

    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 37);

    s = s ^ (s << 7);
    s = s ^ (s >> 11);
    s = s ^ (s << 23);

    round_key = s[37:14];
}

bit<24> feistel_F_round_48(in bit<24> R, in bit<24> round_key) {
    bit<24> rotated = (R << 5) | (R >> 19);
    return rotated ^ round_key;
}

void feistel_round_48(inout bit<24> L, inout bit<24> R, in bit<24> round_key) {
    bit<24> F_out = feistel_F_round_48(R, round_key);
    bit<24> R_new = L ^ F_out;
    L = R;
    R = R_new;
}

void feistel_encrypt_48(inout bit<48> fields, in bit<128> master_key) {
    bit<24> L;
    bit<24> R;
    bit<24> round_key;
    bit<8> i = 0;

    feistel_split_48(L, R, fields);

    feistel_get_round_key_48(master_key, i, round_key);
    feistel_round_48(L, R, round_key);
    i = i + 1;

    feistel_get_round_key_48(master_key, i, round_key);
    feistel_round_48(L, R, round_key);

    feistel_combine_48(L, R, fields);
}

void feistel_decrypt_48(inout bit<48> fields, in bit<128> master_key) {
    bit<24> L;
    bit<24> R;
    bit<24> round_key;
    bit<8> i = 1;

    feistel_split_48(L, R, fields);

    feistel_get_round_key_48(master_key, i, round_key);
    feistel_round_48(R, L, round_key);
    i = i - 1;

    feistel_get_round_key_48(master_key, i, round_key);
    feistel_round_48(R, L, round_key);

    feistel_combine_48(L, R, fields);
}

// Feistel network for 32-bit input/output ///////////////////////////////

void feistel_split_32(out bit<16> L, out bit<16> R, in bit<32> input) {
    L = input[31:16];
    R = input[15:0];
}

void feistel_combine_32(in bit<16> L, in bit<16> R, out bit<32> output) {
    output = (bit<32>)L;
    output = (output << 16) | (bit<32>)R;
}

void feistel_get_round_key_32(in bit<128> master_key, in bit<8> round_index, out bit<16> round_key) {
    bit<128> s = master_key;

    s = s + (bit<128>)round_index;

    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 37);

    s = s ^ (s << 7);
    s = s ^ (s >> 11);
    s = s ^ (s << 23);

    round_key = s[37:22];
}

bit<16> feistel_F_round_32(in bit<16> R, in bit<16> round_key) {
    bit<16> rotated = (R << 5) | (R >> 11);
    return rotated ^ round_key;
}

void feistel_round_32(inout bit<16> L, inout bit<16> R, in bit<16> round_key) {
    bit<16> F_out = feistel_F_round_32(R, round_key);
    bit<16> R_new = L ^ F_out;
    L = R;
    R = R_new;
}

void feistel_encrypt_32(inout bit<32> fields, in bit<128> master_key) {
    bit<16> L;
    bit<16> R;
    bit<16> round_key;
    bit<8> i = 0;

    feistel_split_32(L, R, fields);

    feistel_get_round_key_32(master_key, i, round_key);
    feistel_round_32(L, R, round_key);
    i = i + 1;

    feistel_get_round_key_32(master_key, i, round_key);
    feistel_round_32(L, R, round_key);

    feistel_combine_32(L, R, fields);
}

void feistel_decrypt_32(inout bit<32> fields, in bit<128> master_key) {
    bit<16> L;
    bit<16> R;
    bit<16> round_key;
    bit<8> i = 1;

    feistel_split_32(L, R, fields);

    feistel_get_round_key_32(master_key, i, round_key);
    feistel_round_32(R, L, round_key);
    i = i - 1;

    feistel_get_round_key_32(master_key, i, round_key);
    feistel_round_32(R, L, round_key);

    feistel_combine_32(L, R, fields);
}

// Feistel network for 124-bit input/output //////////////////////////////

void feistel_split_124(out bit<62> L, out bit<62> R, in bit<124> input) {
    L = input[123:62];
    R = input[61:0];
}

void feistel_combine_124(in bit<62> L, in bit<62> R, out bit<124> output) {
    output = (bit<124>)L;
    output = (output << 62) | (bit<124>)R;
}

void feistel_get_round_key_124(in bit<128> master_key, in bit<8> round_index, out bit<62> round_key) {
    bit<128> s = master_key;

    s = s + (bit<128>)round_index;

    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 37);

    s = s ^ (s << 7);
    s = s ^ (s >> 11);
    s = s ^ (s << 23);

    round_key = s[104:43];
}

bit<62> feistel_F_round_124(in bit<62> R, in bit<62> round_key) {
    bit<62> rotated = (R << 5) | (R >> 57);
    return rotated ^ round_key;
}

void feistel_round_124(inout bit<62> L, inout bit<62> R, in bit<62> round_key) {
    bit<62> F_out = feistel_F_round_124(R, round_key);
    bit<62> R_new = L ^ F_out;
    L = R;
    R = R_new;
}

void feistel_encrypt_124(inout bit<124> fields, in bit<128> master_key) {
    bit<62> L;
    bit<62> R;
    bit<62> round_key;
    bit<8> i = 0;

    feistel_split_124(L, R, fields);

    feistel_get_round_key_124(master_key, i, round_key);
    feistel_round_124(L, R, round_key);
    i = i + 1;

    feistel_get_round_key_124(master_key, i, round_key);
    feistel_round_124(L, R, round_key);

    feistel_combine_124(L, R, fields);
}

void feistel_decrypt_124(inout bit<124> fields, in bit<128> master_key) {
    bit<62> L;
    bit<62> R;
    bit<62> round_key;
    bit<8> i = 1;

    feistel_split_124(L, R, fields);

    feistel_get_round_key_124(master_key, i, round_key);
    feistel_round_124(R, L, round_key);
    i = i - 1;

    feistel_get_round_key_124(master_key, i, round_key);
    feistel_round_124(R, L, round_key);

    feistel_combine_124(L, R, fields);
}
