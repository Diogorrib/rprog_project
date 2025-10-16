// feistel_split128_split.p4
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_CUSTOM = 0x88B5;

// Outer headers (minimal)
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// 272-bit payload split into two halves of 136 bits each,
// each half represented as hi:128 + lo:8
header feistel_hdr_t {
    bit<128> left_hi;
    bit<8>   left_lo;
    bit<128> right_hi;
    bit<8>   right_lo;
}

struct headers {
    ethernet_t eth;
    feistel_hdr_t fe;
}

parser MyParser(packet_in packet, out headers hdr, inout standard_metadata_t meta) {
    state start {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            ETHERTYPE_CUSTOM: parse_feistel;
            default: accept;
        }
    }
    state parse_feistel {
        // parse in the same order as packet layout: left(17 bytes) then right(17 bytes)
        packet.extract(hdr.fe.left_hi);
        packet.extract(hdr.fe.left_lo);
        packet.extract(hdr.fe.right_hi);
        packet.extract(hdr.fe.right_lo);
        transition accept;
    }
}

// Helper function: F(R, K) implemented as action inlined (no loops)
control MyIngress(inout headers hdr, inout standard_metadata_t meta) {

    // Round function: F(R, K) -> out_hi(128) , out_lo(8)
    // We implement as an action so we can pass key parts as params.
    action F_apply(
        /* inputs */ bit<128> r_hi, bit<8> r_lo,
        bit<128> k_hi, bit<8> k_lo,
        /* outputs */ out bit<128> out_hi, out bit<8> out_lo)
    {
        bit<128> X_hi = r_hi ^ k_hi;
        bit<8>   X_lo = r_lo ^ k_lo;

        // shift X_lo into the top 8 bits of a 128 bit word
        bit<128> X_lo_ext = (bit<128>) X_lo << 120; // places X_lo at bits [127:120]

        bit<128> mix_hi = X_hi ^ X_lo_ext;
        bit<8>   mix_lo = X_lo ^ (bit<8>) (X_hi & 0xFF);

        out_hi = mix_hi;
        out_lo = mix_lo;
    }

    // Individual round actions: perform one Feistel round, keys passed as params.
    action feistel_round(bit<128> key_hi, bit<8> key_lo) {
        bit<128> F_hi;
        bit<8> F_lo;
        // Compute F(right, key)
        F_apply(hdr.fe.right_hi, hdr.fe.right_lo, key_hi, key_lo, F_hi, F_lo);
        // newRight = left XOR F(right, key)
        bit<128> newR_hi = hdr.fe.left_hi ^ F_hi;
        bit<8>   newR_lo = hdr.fe.left_lo ^ F_lo;
        // rotate halves: L <- R ; R <- newR
        hdr.fe.left_hi = hdr.fe.right_hi;
        hdr.fe.left_lo = hdr.fe.right_lo;
        hdr.fe.right_hi = newR_hi;
        hdr.fe.right_lo = newR_lo;
    }

    apply {
        // --- UNROLLED ROUNDS ---
        // NOTE: keys must be provided by control plane as action parameters when installing table
        // For demo we use literal constants (replace with proper table entries in real use).
        feistel_round(0x00112233445566778899AABBCCDDEEFF, 0x01); // round 0 key_hi, key_lo
        feistel_round(0x0F1E2D3C4B5A69788796A5B4C3D2E1F0, 0x02); // round 1
        feistel_round(0xAABBCCDDEEFF00112233445566778899, 0x03); // round 2
        feistel_round(0x112233445566778899AABBCCDDEEFF00, 0x04); // round 3
        // add more rounds by repeating feistel_round(...) with different keys
    }
}

control MyEgress(inout headers hdr, inout standard_metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        // emit left_hi (16 bytes), left_lo (1 byte), right_hi (16 bytes), right_lo (1 byte)
        packet.emit(hdr.fe.left_hi);
        packet.emit(hdr.fe.left_lo);
        packet.emit(hdr.fe.right_hi);
        packet.emit(hdr.fe.right_lo);
    }
}

V1Switch(MyParser(), MyIngress(), MyEgress(), MyDeparser());
