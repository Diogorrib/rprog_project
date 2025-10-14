/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 =   0x0800;
const bit<16> TYPE_CUSTOM = 0x88B5;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  PROTO_TCP  = 6;
const bit<8>  PROTO_UDP  = 17;
const bit<32> PKT_INSTANCE_TYPE_RESUBMIT = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;   // yes: reveal target device identity or multicast group
    macAddr_t srcAddr;   // yes: reveal source device identity
    bit<16>   etherType; // no: will be a fixed value (TYPE_CUSTOM)
}

header ipv4_t {
    bit<4>    version;        // yes: reveal IP version
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification; // maybe: reveal ordering and link to the same host
    bit<3>    flags;          // yes: allow packet reconstruction
    bit<13>   fragOffset;     // yes: allow packet reconstruction
    bit<8>    ttl;
    bit<8>    protocol;       // yes: reveal the next protocol
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;        // yes: reveal sender IP address
    ip4Addr_t dstAddr;        // yes: reveal target IP address
}

header custom_t {
    bit<128> tag;
    bit<32>  version;
    bit<16>  etherType; // yes: reveal original etherType (and thus the next protocol)
}

header icmp_t {
    bit<8>  type;         // yes: reveal ICMP type
    bit<8>  code;         // yes: reveal reason for message
    bit<16> checksum;
    bit<32> restOfHeader; // yes: reveal info depending on type/code
}

header udp_t {
    bit<16> srcPort; // yes: reveal application/service identity if not ephemeral
    bit<16> dstPort; // yes: reveal application/service identity
    bit<16> length;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;   // yes: reveal application/service identity if not ephemeral
    bit<16> dstPort;   // yes: reveal application/service identity
    bit<32> seqNo;     // yes: reveal ordering and link to the same host
    bit<32> ackNo;     // yes: reveal ordering and link to the same host
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;     // yes: reveal connection state
    bit<16> window;    // maybe: reveal flow control state
    bit<16> checksum;
    bit<16> urgentPtr; // yes: reveal if used or not
}

struct metadata {
    bool    perform_rnd; // whether to perform randomization or not
    bool    is_recirculated; // indicates second processing of the packet
    bool    fetched_version;
    @field_list(1) bit<32>  local_version;
    @field_list(1) bit<128> seed1; // seed to XOR with the nonce
    @field_list(1) bit<128> seed2; // seed to XOR with the nonce and then use to randomize the header fields
    @field_list(1) bit<128> nonce;
}

struct headers {
    ethernet_t  ethernet;
    custom_t    custom;
    ipv4_t      ipv4;
    icmp_t      icmp;
    udp_t       udp;
    tcp_t       tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.is_recirculated = (standard_metadata.instance_type == PKT_INSTANCE_TYPE_RESUBMIT);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_CUSTOM: parse_custom;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_ICMP: parse_icmp;
            PROTO_TCP:  parse_tcp;
            PROTO_UDP:  parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_custom {
        packet.extract(hdr.custom);
        transition select(meta.is_recirculated) {
            true: second_start;
            false: accept;
        }
    }

    // TODO: we need to be able to deteministically obtain protocol type
    //       from each header (starting from custom) from the randomization
    //       process, so we can parse the correct headers and then derandomize
    //       them in the ingress processing. (e.g., reserve a derivation of
    //       the original enc_seed to encode all protocols)
    //
    // Note: for now, it is only required to obtain the etherType from
    //       the custom header (i.e. 16 bits) and the protocol from
    //       the IPv4 header (i.e. 8 bits)

    state second_start {
        transition select(hdr.custom.etherType) { // FIXME: requires derandomization
            TYPE_IPV4: parse_ipv4; // FIXME: requires different function or generalization of the current one
            default: accept;
        }
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

    action ipv4_forward(macAddr_t srcAddr,
                        macAddr_t dstAddr,
                        egressSpec_t port,
                        bit<1> perform_rnd) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.perform_rnd = (bool) perform_rnd;
    }

    action check_update_from_packet(in bit<32> in_port_idx,
                                    in bit<32> packet_version,
                                    out bool to_update) {
        to_update = false;
        curr_version.read(meta.local_version, in_port_idx);
        meta.fetched_version = true;
        if (meta.local_version < packet_version) {
            to_update = true;
        }
    }

    /* Needs to be performed after forwarding action sets the egress port */
    action check_update_from_ctrl(in bit<32> out_port_idx,
                                  out bool to_update,
                                  out bit<32> new_version) {
        to_update = false;
        ctrl_version.read(new_version, out_port_idx);
        if (meta.local_version < new_version) {
            to_update = true;
        }
    }

    action update_version(bit<32> port_index, bit<32> new_version) {
        curr_version.write(port_index, new_version);
        meta.local_version = new_version;
    }

    action update_prev_seed(bit<32> port_index, bit<32> index) {
        bit<128> aux;
        bit<32>  i;

        i = port_index*2 + index;
        curr_seed.read(aux, i);
        prev_seed.write(i, aux);
    }

    action update_curr_seed(bit<32> port_index, bit<32> index) {
        bit<128> seed;
        bit<32>  aux;
        bit<32>  i;

        i = (port_index*2 + index)*4;
        next_seed.read(aux, i);
        seed = (bit<128>)aux;
        next_seed.read(aux, i+1);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, i+2);
        seed = (seed << 32) | (bit<128>)aux;
        next_seed.read(aux, i+3);
        seed = (seed << 32) | (bit<128>)aux;
        i = i / 4;
        curr_seed.write(i, seed);
    }

    action get_prev_seed(in bit<32> port_index, in bit<32> index, out bit<128> seed) {
        bit<32> i;
        i = port_index*2 + index;
        prev_seed.read(seed, i);
    }

    action get_curr_seed(in bit<32> port_index, in bit<32> index, out bit<128> seed) {
        bit<32> i;
        i = port_index*2 + index;
        curr_seed.read(seed, i);
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
        bit<32> new_version;
        bool to_update;

        // required initializations across recirculations
        meta.fetched_version = false;

        // fetch version and nonce from packet: if first processing
        if (!meta.is_recirculated && hdr.custom.isValid()) {
            port_index = (bit<32>) standard_metadata.ingress_port - 1;
            check_update_from_packet(port_index, hdr.custom.version, to_update);
            if (to_update) {
                update_prev_seed(port_index, 0);
                update_prev_seed(port_index, 1);
                update_curr_seed(port_index, 0);
                update_curr_seed(port_index, 1);
                update_version(port_index, hdr.custom.version); // need to be the last operation
            }

            // here it can never be lower since we perform the update above
            if (meta.local_version == hdr.custom.version) {
                get_curr_seed(port_index, 0, meta.seed1);
                get_curr_seed(port_index, 1, meta.seed2);
            } else { // meta.local_version > hdr.custom.version
                get_prev_seed(port_index, 0, meta.seed1);
                get_prev_seed(port_index, 1, meta.seed2);
            }
            // TODO: extract nonce from tag and save in metadata
            resubmit_preserving_field_list(1); // go back to parse remaining headers
            return;
        }

        // derandomize the packet: if second processing
        if (meta.is_recirculated) {
            // TODO: derandomize the packet here using meta.nonce and meta.seed2
        }

        // perform forwarding actions
        if (hdr.ipv4.isValid()) {
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
        }

        // perform randomization
        if (meta.perform_rnd) {
            port_index = (bit<32>) standard_metadata.egress_spec - 1;
            if (!meta.is_recirculated && !meta.fetched_version) // only fetch if not done before
                curr_version.read(meta.local_version, port_index);
            check_update_from_ctrl(port_index, to_update, new_version);
            if (to_update) {
                update_prev_seed(port_index, 0);
                update_prev_seed(port_index, 1);
                update_curr_seed(port_index, 0);
                update_curr_seed(port_index, 1);
                update_version(port_index, new_version); // need to be the last operation
            }
            get_curr_seed(port_index, 0, meta.seed1);
            get_curr_seed(port_index, 1, meta.seed2);
            // TODO: randomize the packet here generating a nonce and
            //       then using (seed2 XOR nonce) to randomize the header fields
            //       also, need to add the custom header with version,
            //       original etherType, and tag (= nonce XOR seed1)
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
        // TODO: emit custom when to be randomized
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
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
