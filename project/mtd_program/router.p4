/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header custom_t {
    bit<32> version;
    bit<128> tag;
}

struct metadata {
    bit<32>  local_version;
    bit<32>  port_index;
    bit<128> seed1; /* seed for the anonymization */
    bit<128> seed2; /* seed for the anonymization */
    bit<128> seed1rev; /* seed for the deanonymization */
    bit<128> seed2rev; /* seed for the deanonymization */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    custom_t     custom;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // register<bit<32>>(6*4) prev_seed; // up to 3 links each with a seed-pair (128 bits = 4x32 bits)
    register<bit<128>>(6) prev_seed;
    // register<bit<32>>(6*4) curr_seed; // up to 3 links each with a seed-pair (128 bits = 4x32 bits)
    register<bit<128>>(6) curr_seed;
    register<bit<32>>(6*4) next_seed; // up to 3 links each with a seed-pair (128 bits = 4x32 bits)
    register<bit<32>>(1*4+1) base_prng; // 128 bits = 4x32 bits + 1 bit for the state/counter
    register<bit<32>>(3)  curr_version; // up to 3 links
    register<bit<32>>(3)  ctrl_version; // up to 3 links

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* Needs to be performed after forwarding action sets the egress port */
    action check_update_version(in bit<32> port_index, out bool to_update, out bit<32> new_version) {
        ctrl_version.read(new_version, port_index);
        curr_version.read(meta.local_version, port_index);
        if (new_version > meta.local_version)
            to_update = true;
        else
            to_update = false;
    }

    action update_version(bit<32> port_index, bit<32> new_version) {
        curr_version.write(port_index, new_version);
        meta.local_version = new_version;
    }

    /* action update_prev_seed(bit<32> index) {
        bit<32> aux;

        curr_seed.read(aux, index);
        prev_seed.write(index, aux);
        curr_seed.read(aux, index+1);
        prev_seed.write(index+1, aux);
        curr_seed.read(aux, index+2);
        prev_seed.write(index+2, aux);
        curr_seed.read(aux, index+3);
        prev_seed.write(index+3, aux);
    } */

    action update_prev_seed_new(bit<32> index) {
        bit<128> aux;

        curr_seed.read(aux, index);
        prev_seed.write(index, aux);
    }

    /* action update_curr_seed(bit<32> index) {
        bit<32> aux;

        next_seed.read(aux, index);
        curr_seed.write(index, aux);
        next_seed.read(aux, index+1);
        curr_seed.write(index+1, aux);
        next_seed.read(aux, index+2);
        curr_seed.write(index+2, aux);
        next_seed.read(aux, index+3);
        curr_seed.write(index+3, aux);
    } */

    action update_curr_seed_new(bit<32> index) {
        bit<32> aux;
        bit<128> seed;

        next_seed.read(aux, index);
        seed = (bit<128>)aux;
        next_seed.read(aux, index+1);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, index+2);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, index+3);
        seed = (seed << 32) | (bit<128>)aux;
        curr_seed.write(index, seed);
    }

    /* action get_prev_seed(in bit<32> index, out bit<128> seed) {
        bit<32> aux;

        prev_seed.read(aux, index);
        seed = (bit<128>)aux;
        prev_seed.read(aux, index+1);
        seed = (seed << 32) | (bit<128>)aux;
        prev_seed.read(aux, index+2);
        seed = (seed << 32) | (bit<128>)aux;
        prev_seed.read(aux, index+3);
        seed = (seed << 32) | (bit<128>)aux;
    } */

    action get_prev_seed_new(in bit<32> index, out bit<128> seed) {
        prev_seed.read(seed, index);
    }

    /* action get_curr_seed(in bit<32> index, out bit<128> seed) {
        bit<32> aux;

        curr_seed.read(aux, index);
        seed = (bit<128>)aux;
        curr_seed.read(aux, index+1);
        seed = (seed << 32) | (bit<128>)aux;
        curr_seed.read(aux, index+2);
        seed = (seed << 32) | (bit<128>)aux;
        curr_seed.read(aux, index+3);
        seed = (seed << 32) | (bit<128>)aux;
    } */

    action get_curr_seed_new(in bit<32> index, out bit<128> seed) {
        curr_seed.read(seed, index);
    }

    action get_next_seed(in bit<32> index, out bit<128> seed) {
        bit<32> aux;

        next_seed.read(aux, index);
        seed = (bit<128>)aux;
        next_seed.read(aux, index+1);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, index+2);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, index+3);
        seed = (seed << 32) | (bit<128>)aux;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_reverse {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        bit<32> port_index;
        bit<32> idx;
        bit<32> new_version;
        bool to_update;

        // TODO: check if further parsing is required (consider resubmit or recirculate)

        if (hdr.custom.isValid()) { // perform deanonymization if custom header is present
            port_index = (bit<32>) standard_metadata.ingress_port - 1;
            check_update_version(port_index, to_update, new_version);
            /* if (to_update) {
                idx = (port_index*2 + 0)*4;
                update_prev_seed(idx);
                update_curr_seed(idx);
                idx = (port_index*2 + 1)*4;
                update_prev_seed(idx);
                update_curr_seed(idx);
                update_version(port_index, new_version); // need to be the last operation
            }

            if (meta.local_version == hdr.custom.version) {
                idx = (port_index*2 + 0)*4;
                get_curr_seed(idx, meta.seed1rev);
                idx = (port_index*2 + 1)*4;
                get_curr_seed(idx, meta.seed2rev);
            } else if (meta.local_version > hdr.custom.version) {
                idx = (port_index*2 + 0)*4;
                get_prev_seed(idx, meta.seed1rev);
                idx = (port_index*2 + 1)*4;
                get_prev_seed(idx, meta.seed2rev);
            } else { // meta.local_version < hdr.custom.version
                idx = (port_index*2 + 0)*4;
                get_next_seed(idx, meta.seed1rev);
                idx = (port_index*2 + 1)*4;
                get_next_seed(idx, meta.seed2rev);
            } */

            if (to_update) {
                idx = port_index*2 + 0;
                update_prev_seed_new(idx);
                update_curr_seed_new(idx);
                idx = port_index*2 + 1;
                update_prev_seed_new(idx);
                update_curr_seed_new(idx);
                update_version(port_index, new_version); // need to be the last operation
            }

            if (meta.local_version == hdr.custom.version) {
                idx = port_index*2 + 0;
                get_curr_seed_new(idx, meta.seed1rev);
                idx = port_index*2 + 1;
                get_curr_seed_new(idx, meta.seed2rev);
            } else if (meta.local_version > hdr.custom.version) {
                idx = port_index*2 + 0;
                get_prev_seed_new(idx, meta.seed1rev);
                idx = port_index*2 + 1;
                get_prev_seed_new(idx, meta.seed2rev);
            } else { // meta.local_version < hdr.custom.version
                idx = (port_index*2 + 0)*4;
                get_next_seed(idx, meta.seed1rev);
                idx = (port_index*2 + 1)*4;
                get_next_seed(idx, meta.seed2rev);
            }
            // TODO: perform deanonymization of the packet here
        }

        if (hdr.ipv4.isValid()) { // perform routing and anonymization of the recovered packet
            if (hdr.ipv4.ttl <= 1) {
                drop();
                return;
            }

            if (!(ipv4_exact.apply().hit ||
                  ipv4_lpm.apply().hit ||
                  ipv4_reverse.apply().hit)) {
                drop();
                return;
            }

            port_index = (bit<32>) standard_metadata.egress_spec - 1;
            check_update_version(port_index, to_update, new_version);
            /* if (to_update) {
                idx = (port_index*2 + 0)*4;
                update_prev_seed(idx);
                update_curr_seed(idx);
                idx = (port_index*2 + 1)*4;
                update_prev_seed(idx);
                update_curr_seed(idx);
                update_version(port_index, new_version); // need to be the last operation
            }
            idx = (port_index*2 + 0)*4;
            get_curr_seed(idx, meta.seed1);
            idx = (port_index*2 + 1)*4;
            get_curr_seed(idx, meta.seed2); */

            if (to_update) {
                idx = port_index*2 + 0;
                update_prev_seed_new(idx);
                update_curr_seed_new(idx);
                idx = port_index*2 + 1;
                update_prev_seed_new(idx);
                update_curr_seed_new(idx);
                update_version(port_index, new_version); // need to be the last operation
            }
            idx = port_index*2 + 0;
            get_curr_seed_new(idx, meta.seed1);
            idx = port_index*2 + 1;
            get_curr_seed_new(idx, meta.seed2);
            // TODO: perform anonymization of the packet here
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
