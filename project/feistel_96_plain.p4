

#include <core.p4>

const bit<16> ETHERTYPE_FEISTEL96 = 0xFE96;

// =================== Headers & Metadata ===================

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header feistel96_t {
    bit<48> L;
    bit<48> R;
}

struct headers {
    ethernet_t   ethernet;
    feistel96_t  f96;
}

struct metadata_t {
    // control flags
    bit<1> do_decrypt;  // 0 = encrypt, 1 = decrypt

    // scratch temporaries
    bit<48>  t48;
    bit<64>  t64;
    bit<128> t128a;
    bit<128> t128b;

    // round keys
    bit<128> k1;
    bit<128> k2;
    bit<128> k3;
    bit<128> k4;
    bit<128> k5;
    bit<128> k6;
    bit<128> k7;
    bit<128> k8;
}


/* 

Example of struct usage

struct algo_state_t {
    // seed (128-bit) split as two 64-bit words set by table, then concatenated
    bit<64> seed_hi;
    bit<64> seed_lo;

    // derived full seed
    bit<128> seed;
    bit<128> k1;
    bit<128> k2;
    bit<128> k3;
    bit<128> k4;
    bit<128> k5;
    bit<128> k6;
    bit<128> k7;
    bit<128> k8;
}

void something(inout algo_state_t s) {
    s.k1 = 0;
    s.k2 = 0;
    s.k3 = 0;
    s.k4 = 0;
    s.k5 = 0;
    s.k6 = 0;
    s.k7 = 0;
    s.k8 = 0;
} */

struct standard_metadata_t {
    bit<9>    ingress_port;
    bit<9>    egress_spec;
    bit<9>    egress_port;
    bit<32>   instance_type;
    bit<1>    drop;
    bit<16>   recirculate_port;
    bit<32>   packet_length;
    bit<32>   enq_timestamp;
    bit<19>   enq_qdepth;
    bit<32>   deq_timedelta;
    bit<19>   deq_qdepth;
    bit<48>   ingress_global_timestamp;
    bit<32>   lf_field_list;
    bit<4>    mcast_grp;
    bit<4>    egress_rid;
    bit<1>    checksum_error;
    bit<3>    priority;
}

// =================== Parser ===================

parser ParserImpl(packet_in packet,
                  out headers hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_FEISTEL96: parse_feistel96;
            default: accept;
        }
    }

    state parse_feistel96 {
        packet.extract(hdr.f96);
        transition accept;
    }
}

// =================== Checksum (unused) ===================

control VerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}
control ComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}

// =================== Ingress: Feistel logic ===================

bit<128> rng128_forward(bit<128> s) {
    s = s + OFFSET128;
    s = s ^ (s << 23);
    s = s ^ (s >> 17);
    s = s ^ (s << 31);
    return s;
}

control IngressImpl(inout headers hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata)
{

    const bit<128> OFFSET128 = 0x0123456789ABCDEF0FEDCBA987654321;
    const bit<4>   ROUNDS = 8;


    function bit<48> F_round(bit<48> R, bit<128> round_key) {
        bit<128> r128 = { (bit<80>)0, R };
        bit<128> mixed  = rng128_forward(r128 ^ round_key);
        bit<128> mixed2 = rng128_forward(mixed ^ round_key);
        bit<128> x = mixed ^ mixed2;
        bit<64> x_lo = (bit<64>) x;
        bit<64> x_hi = (bit<64>) (x >> 64);
        bit<64> reduced = x_lo ^ x_hi;
        return (bit<48>) reduced;
    }

    action set_seed_and_mode(bit<1> do_decrypt,
                             bit<64> seed_hi,
                             bit<64> seed_lo)
    {
        meta.do_decrypt = do_decrypt;
        meta.seed_hi = seed_hi;
        meta.seed_lo = seed_lo;
        meta.seed = { meta.seed_hi, meta.seed_lo };
    }

    table config_table {
        key = {
            hdr.ethernet.etherType : exact; // simple demo key
        }
        actions = {
            set_seed_and_mode;
            NoAction;
        }
        const entries = {
            (ETHERTYPE_FEISTEL96) : set_seed_and_mode(0 , 0x1234567890ABCDEF, 0x0FEDCBA098765432);
        }
        size = 1;
        default_action = NoAction();
    }

    function void derive_round_keys() {
        bit<128> s = meta.seed;
        s = rng128_forward(s); meta.k1 = s;
        s = rng128_forward(s); meta.k2 = s;
        s = rng128_forward(s); meta.k3 = s;
        s = rng128_forward(s); meta.k4 = s;
        s = rng128_forward(s); meta.k5 = s;
        s = rng128_forward(s); meta.k6 = s;
        s = rng128_forward(s); meta.k7 = s;
        s = rng128_forward(s); meta.k8 = s;
    }

    function void encrypt96(inout bit<48> L, inout bit<48> R) {
        bit<48> t, newR;

        t = F_round(R, meta.k1); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k2); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k3); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k4); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k5); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k6); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k7); newR = L ^ t; L = R; R = newR;
        t = F_round(R, meta.k8); newR = L ^ t; L = R; R = newR;
    }

    function void decrypt96(inout bit<48> L, inout bit<48> R) {
        bit<48> L_prev, R_prev, t;

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

    apply {
        // basic forwarding (not focus of demo)
        standard_metadata.egress_spec = 1;

        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == ETHERTYPE_FEISTEL96
            && hdr.f96.isValid()) {

            // Load defaults or CP-provided seed/mode
            apply(config_table);

            // If control-plane didn't set seed, build it from defaults in table (already done).

            // Derive round keys from 128-bit seed
            derive_round_keys();

            // Execute Feistel rounds
            bit<48> L = hdr.f96.L;
            bit<48> R = hdr.f96.R;

            if (meta.do_decrypt == 1) {
                decrypt96(L, R);
            } else {
                encrypt96(L, R);
            }

            // Store back
            hdr.f96.L = L;
            hdr.f96.R = R;
        }
    }
}

// =================== Egress & Deparser ===================

control EgressImpl(inout headers hdr,
                   inout metadata_t meta,
                   inout standard_metadata_t standard_metadata)
{
    apply { }
}

control DeparserImpl(packet_out packet, in headers hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.f96.isValid()) {
            packet.emit(hdr.f96);
        }
    }
}

// =================== Switch package ===================

V1Switch(ParserImpl(),
         VerifyChecksum(),
         IngressImpl(),
         EgressImpl(),
         ComputeChecksum(),
         DeparserImpl()) main;

/* 

FROM HERE EVERYTHING MAY BE WRONG --- IGNORE ---


struct pnrg_state_t {
    bit<128> k1;
    bit<128> k2;
    bit<128> k3;
    bit<128> k4;
    bit<128> k5;
    bit<128> k6;
    bit<128> k7;
    bit<128> k8;
}

bit<128> rng128_forward(bit<128> s) {
    s = s + OFFSET128;
    s = s ^ (s << 23);
    s = s ^ (s >> 17);
    s = s ^ (s << 31);
    return s;
}

void derive_round_keys(bit<128> s, inout pnrg_state_t meta) {
    s = rng128_forward(s, meta.k1); meta.k1 = s;
    s = rng128_forward(s, meta.k2); meta.k2 = s;
    s = rng128_forward(s, meta.k3); meta.k3 = s;
    s = rng128_forward(s, meta.k4); meta.k4 = s;
    s = rng128_forward(s, meta.k5); meta.k5 = s;
    s = rng128_forward(s, meta.k6); meta.k6 = s;
    s = rng128_forward(s, meta.k7); meta.k7 = s;
    s = rng128_forward(s, meta.k8); meta.k8 = s;
}

bit<48> F_round(bit<48> R, bit<128> round_key) {
    bit<128> r128 = { (bit<80>)0, R };
    bit<128> mixed  = rng128_forward(r128 ^ round_key);
    bit<128> mixed2 = rng128_forward(mixed ^ round_key);
    bit<128> x = mixed ^ mixed2;
    bit<64> x_lo = (bit<64>) x;
    bit<64> x_hi = (bit<64>) (x >> 64);
    bit<64> reduced = x_lo ^ x_hi;
    return (bit<48>) reduced;
}

void encrypt96(inout bit<48> L, inout bit<48> R) {
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

void round_d(inout bit<48> L_prev, bit<48> R_prev,
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
}
 */
