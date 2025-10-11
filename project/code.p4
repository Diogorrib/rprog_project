/*
 * rng16_32.p4
 * Translation of reversible RNG example from C to P4_16
 * (For testing in BMv2 simple_switch)
 */

#include <core.p4>

// --- Constants ---
const bit<16> OFFSET16 = 12345;
const bit<32> OFFSET32 = 987654321;

// --- 16-bit reversible RNG ---
bit<16> rng16_forward(bit<16> input) {
    bit<16> s = input + OFFSET16;
    s = s ^ (s << 7);
    s = s ^ (s >> 9);
    s = s ^ (s << 8);
    return s;
}

bit<16> rng16_inverse(bit<16> output) {
    bit<16> s = output;
    s = s ^ (s << 8);
    s = s ^ (s >> 9);
    s = s ^ (s << 7);
    s = s ^ (s << 14);
    return s - OFFSET16;
}

// --- 32-bit reversible RNG ---
bit<32> rng32_forward(bit<32> input) {
    bit<32> s = input + OFFSET32;
    s = s ^ (s << 13);
    s = s ^ (s >> 17);
    s = s ^ (s << 5);
    return s;
}

bit<32> rng32_inverse(bit<32> output) {
    bit<32> s = output;
    s = s ^ (s << 5);  s = s ^ (s << 10);  s = s ^ (s << 20);
    s = s ^ (s >> 17);
    s = s ^ (s << 13); s = s ^ (s << 26);
    return s - OFFSET32;
}

// --- Headers for demonstration ---
header demo_t {
    bit<8> in8_1;
    bit<8> in8_2;
    bit<16> in16;
    bit<32> in32;
    bit<48> num;
}

struct metadata_t {
    bit<16> in16_combined;
    bit<32> in32_l;
    bit<16> in16_r;
    bit<16> r16_combined;
    bit<16> r16;
    bit<32> r32;
    bit<16> inv16_combined;
    bit<16> inv16;
    bit<32> inv32;
    bit<8> inv8_1;
    bit<8> inv8_2;
    bit<64> recombined;
}

// --- Parser ---
parser MyParser(packet_in pkt, out demo_t hdr, inout metadata_t meta, inout standard_metadata_t sm) {
    state start {
        pkt.extract(hdr);
        transition accept;
    }
}

// --- Ingress control ---
control MyIngress(inout demo_t hdr, inout metadata_t meta, inout standard_metadata_t sm) {
    apply {
        // Combine bytes
        meta.in16_combined = (bit<16>)(hdr.in8_1) << 8 | hdr.in8_2;

        // Split 48-bit number
        meta.in32_l = (bit<32>)((hdr.num >> 16) & 0xFFFFFFFF);
        meta.in16_r = (bit<16>)(hdr.num & 0xFFFF);

        // Apply RNGs
        meta.r16_combined = rng16_forward(meta.in16_combined);
        meta.r16 = rng16_forward(meta.in16_r);
        meta.r32 = rng32_forward(meta.in32_l);

        // Inverse RNGs
        meta.inv16_combined = rng16_inverse(meta.r16_combined);
        meta.inv16 = rng16_inverse(meta.r16);
        meta.inv32 = rng32_inverse(meta.r32);

        // Reconstruct original data
        meta.inv8_1 = (bit<8>)(meta.inv16_combined >> 8);
        meta.inv8_2 = (bit<8>)(meta.inv16_combined & 0xFF);
        meta.recombined = ((bit<64>)(meta.inv32) << 16) | meta.inv16;

        // Example “printf” equivalent (set egress port based on success)
        if (meta.inv8_1 == hdr.in8_1 && meta.inv8_2 == hdr.in8_2) {
            if (meta.recombined == hdr.num)
                sm.egress_spec = 1;  // success
            else
                sm.egress_spec = 2;  // recombine failed
        } else {
            sm.egress_spec = 3; // byte mismatch
        }
    }
}

// --- Egress and Deparser (pass-through) ---
control MyEgress(inout demo_t hdr, inout metadata_t meta, inout standard_metadata_t sm) { apply { } }

control MyDeparser(packet_out pkt, in demo_t hdr) {
    apply { pkt.emit(hdr); }
}

// --- Pipeline ---
V1Switch(MyParser(), MyIngress(), MyEgress(), MyDeparser()) main;