/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define FIELD_LIST_ID 1

const bit<16> TYPE_IPV4 =   0x0800;
const bit<16> TYPE_CUSTOM = 0x88B5;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  PROTO_TCP  = 6;
const bit<8>  PROTO_UDP  = 17;

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
    @field_list(FIELD_LIST_ID)
    bool     is_second_parse;

    @field_list(FIELD_LIST_ID)
    bit<32>  local_version;

    @field_list(FIELD_LIST_ID)
    bit<128> seed1; // seed to XOR with the nonce

    @field_list(FIELD_LIST_ID)
    bit<128> seed2; // seed to XOR with the nonce and then use to randomize the header fields

    @field_list(FIELD_LIST_ID)
    bit<128> nonce;

    bool     perform_rnd;
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

    bit<128> enc_seed;

    state start {
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
        transition parse_ipv4_next;
    }

    state parse_ipv4_next {
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

    /* As this implementation goal is to randomize fields in the headers,
       including the protocols in use, so it makes it more difficult for
       malicious actors to identify them (and thus launch attacks),
       we need to extract local secret information to recover the original
       etherType and protocol information. However, this implies reading
       from registers, operation that is not supported in the parser for
       the target we are using.
       To work around this limitation, we perform a first parse of the
       headers that are always present (ethernet and custom), then the
       custom.tag enables the derivation of the original enc_seed, from
       a local secret stored in registers.
       Then a second parse is triggered through a resubmit, where the
       original etherType and protocol fields can be recovered and the
       remaining headers parsed accordingly.
       In summary we require the following steps:
       -> first_parse
           -> first_processing (extract secrets, derive seeds and save in metadata)
               -> second_parse (use metadata to recover original fields)
                   -> second_processing and then deparsing as usual
    */
    state parse_custom {
        packet.extract(hdr.custom);
        transition select(meta.is_second_parse) {
            true: second_start;
            false: accept;
        }
    }

    state second_start {
        enc_seed = meta.nonce ^ meta.seed2;
        hdr.ethernet.etherType = hdr.custom.etherType ^ enc_seed[15:0];
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_special_ipv4;
            default: accept;
        }
    }

    state parse_special_ipv4 {
        packet.extract(hdr.ipv4);
        hdr.ipv4.protocol = hdr.ipv4.protocol ^ enc_seed[23:16];
        transition parse_ipv4_next;
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

    /* We split 32-bit registers to store 128-bit values to allow use from CLI,
       as we explain p4runtime does not implement this operation yet, so CLI is the workaround.
       However, CLI can only convert up to 64-bit unsigned values, so 32-bit was the highest
       power of 2 we could use.
       128-bit registers that did not require runtime intervention were not split. */
    register<bit<128>>(6) prev_seed; // up to 3 links each with a seed-pair (128 bits)
    register<bit<128>>(6) curr_seed; // up to 3 links each with a seed-pair (128 bits)
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
        if (meta.local_version < packet_version) {
            to_update = true;
        }
    }

    /* Needs to be performed after forwarding action sets the egress port */
    action check_update_from_ctrl(in bit<32> out_port_idx,
                                  out bool to_update,
                                  out bit<32> new_version) {
        to_update = false;
        curr_version.read(meta.local_version, out_port_idx);
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

    action get_new_nonce(out bit<128> nonce) {
        bit<32>  aux;

        base_prng.read(aux, 0);
        nonce = (bit<128>)aux;
        base_prng.read(aux, 1);
        nonce = (nonce << 32) | (bit<128>)aux;
        base_prng.read(aux, 2);
        nonce = (nonce << 32) | (bit<128>)aux;
        base_prng.read(aux, 3);
        nonce = (nonce << 32) | (bit<128>)aux;
        base_prng.read(aux, 4);
        aux = aux + 1;
        base_prng.write(4, aux);
        nonce = nonce ^ (bit<128>)aux; // FIXME: use a better PRNG
    }

    action randomize_fields(bit<128> enc_seed) {
        // TODO: implement field randomization for fields marked as "yes" in the header definitions
    }

    action derandomize_fields(bit<128> enc_seed) {
        // TODO: implement field derandomization for fields marked as "yes" in the header definitions
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
        bit<128> enc_seed;
        bit<32>  port_index;
        bit<32>  new_version;
        bool     to_update;

        // derandomization section
        if (hdr.custom.isValid()) {

            // secret fetching and seed updating
            if (!meta.is_second_parse) {
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

                meta.nonce = hdr.custom.tag ^ meta.seed1;
                meta.is_second_parse = true;
                resubmit_preserving_field_list(FIELD_LIST_ID); // We require this resubmit as we explain above in the parser
                return;

            // derandomization of headers (except etherType and protocol, done in the parser)
            } else {
                derandomize_fields(meta.nonce ^ meta.seed2);
                hdr.custom.setInvalid();
            }
        }

        // forwarding section
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

        // randomization section
        if (meta.perform_rnd) {
            port_index = (bit<32>) standard_metadata.egress_spec - 1;
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
            get_new_nonce(meta.nonce);

            enc_seed = meta.nonce ^ meta.seed2;
            randomize_fields(enc_seed);

            hdr.custom.setValid();
            hdr.custom.version = meta.local_version;
            hdr.custom.tag = meta.nonce ^ meta.seed1;
            hdr.custom.etherType = hdr.ethernet.etherType ^ enc_seed[15:0];
            hdr.ethernet.etherType = TYPE_CUSTOM;
            hdr.ipv4.protocol = hdr.ipv4.protocol ^ enc_seed[23:16];
        } else {
            hdr.custom.setInvalid();
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
        packet.emit(hdr.custom);
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
