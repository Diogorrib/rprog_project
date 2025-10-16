// feistel_p4.p4 - minimal example showing 4 unrolled Feistel rounds on 272-bit header
#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_CUSTOM = 0x88B5;

// 272-bit header split into two 136-bit halves
header feistel_hdr_t {
    bit<136> left;   // L
    bit<136> right;  // R
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
        packet.extract(hdr.fe);
        transition accept;
    }
}

// Helper: rotate-left for bit sizes not power-of-two
// Pseudo: rol(x, n, width) = ((x << n) | (x >> (width - n))) & mask
// We'll implement inline with shifts and ORs.

control MyIngress(inout headers hdr, inout standard_metadata_t meta) {
    // Round function: F(R, K) = rol( R ^ Kext, rot )  where Kext is 136-bit extension of 128-bit key
    // We'll supply each 128-bit key (k0..k3) as action params; inside P4 we extend to 136 bits.

    action feistel_round_0(bit<128> k0) {
        bit<136> Kext = { (bit<8>)0, k0 }; // concat an 8-bit zero to make 136 bits
        bit<136> X = hdr.fe.right ^ Kext;
        // rotate-left by 13 (example)
        bit<136> Xl = (bit<136>)((X << 13) | (X >> (136 - 13)));
        bit<136> newR = hdr.fe.left ^ Xl;
        hdr.fe.left = hdr.fe.right;
        hdr.fe.right = newR;
    }

    action feistel_round_1(bit<128> k1) {
        bit<136> Kext = { (bit<8>)0, k1 };
        bit<136> X = hdr.fe.right ^ Kext;
        bit<136> Xl = (bit<136>)((X << 17) | (X >> (136 - 17)));
        bit<136> newR = hdr.fe.left ^ Xl;
        hdr.fe.left = hdr.fe.right;
        hdr.fe.right = newR;
    }

    action feistel_round_2(bit<128> k2) {
        bit<136> Kext = { (bit<8>)0, k2 };
        bit<136> X = hdr.fe.right ^ Kext;
        bit<136> Xl = (bit<136>)((X << 7) | (X >> (136 - 7)));
        bit<136> newR = hdr.fe.left ^ Xl;
        hdr.fe.left = hdr.fe.right;
        hdr.fe.right = newR;
    }

    action feistel_round_3(bit<128> k3) {
        bit<136> Kext = { (bit<8>)0, k3 };
        bit<136> X = hdr.fe.right ^ Kext;
        bit<136> Xl = (bit<136>)((X << 29) | (X >> (136 - 29)));
        bit<136> newR = hdr.fe.left ^ Xl;
        hdr.fe.left = hdr.fe.right;
        hdr.fe.right = newR;
    }

    // A table to invoke the four rounds with the keys supplied by control plane.
    // You can also break this into separate tables if you prefer.
    table run_feistel {
        actions = {
            feistel_round_0;
            feistel_round_1;
            feistel_round_2;
            feistel_round_3;
            NoAction;
        }
        size = 1;
        default_action = NoAction();
    }

    apply {
        // To run all 4 rounds in order, the control plane will install an entry
        // that invokes the four actions sequentially. Because tables apply only one action per match,
        // the trick is to directly call the actions here in sequence (unrolled), or chain tables.
        // Simpler: call the actions directly (unrolled) with action parameters read from metadata.
        // We assume the control plane has written keys into metadata registers (or action params).
        // For clarity here, we'll call placeholders (actual keys must be provided by control-plane via a table)
        // Example direct calls (replace k0..k3 with constants or use tables to set them):
        // feistel_round_0(k0);
        // feistel_round_1(k1);
        // feistel_round_2(k2);
        // feistel_round_3(k3);

        // For this illustrative example we'll assume keys are given as constant literals:
        feistel_round_0(0x00112233445566778899AABBCCDDEEFF);
        feistel_round_1(0x0F1E2D3C4B5A69788796A5B4C3D2E1F0);
        feistel_round_2(0xAABBCCDDEEFF00112233445566778899);
        feistel_round_3(0x112233445566778899AABBCCDDEEFF00);
    }
}

control MyEgress(inout headers hdr, inout standard_metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.fe);
    }
}

V1Switch(MyParser(), MyIngress(), MyEgress(), MyDeparser());
