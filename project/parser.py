from binascii import unhexlify

"""
Helper file to understand the packet structure from raw data.
Insert the input packet hex string/stream below.
- For packets that are in plain, set parse_type = "default".
- For packets that encapsulate an ICMP packet, set parse_type = "parse_icmp".
- For packets that encapsulate a UDP packet, set parse_type = "parse_udp".
- For packets that encapsulate a TCP packet, set parse_type = "parse_tcp".
- For other types of packets, extend the parser as needed.
"""

input_packet = ""
parse_type = "default"

hexstr = input_packet[2:] if input_packet.startswith("0x") else input_packet
data = unhexlify(hexstr)

def parse_ethernet(packet, offset):
    dst_mac = ':'.join(f"{b:02x}" for b in packet[offset:offset+6])
    src_mac = ':'.join(f"{b:02x}" for b in packet[offset+6:offset+12])
    ethertype = '0x' + packet[offset+12:offset+14].hex()
    parsed = {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ethertype": ethertype
    }
    return parsed, offset + 14

def parse_custom_t(packet, offset):
    tag = packet[offset:offset+16]
    version = int.from_bytes(packet[offset+16:offset+20], byteorder='big')
    etherType = '0x' + packet[offset+20:offset+22].hex()
    parsed = {
        "tag": tag.hex(),
        "version": version,
        "etherType": etherType
    }
    return parsed, offset + 22

def parse_ipv4_fixed(packet, offset):
    version = (packet[offset] >> 4) & 0xF
    ihl = packet[offset] & 0xF
    diffserv = packet[offset+1]
    totalLen = int.from_bytes(packet[offset+2:offset+4], 'big')
    identification = int.from_bytes(packet[offset+4:offset+6], 'big')
    flags = packet[offset+6] >> 5
    fragOffset = ((packet[offset+6] & 0x1F) << 8) | packet[offset+7]
    ttl = packet[offset+8]
    protocol = packet[offset+9]
    hdrChecksum = int.from_bytes(packet[offset+10:offset+12], 'big')
    srcAddr = '.'.join(str(b) for b in packet[offset+12:offset+16])
    dstAddr = '.'.join(str(b) for b in packet[offset+16:offset+20])

    parsed = {
        "version": version,
        "ihl": ihl,
        "diffserv": f"0x{diffserv:02X}",
        "totalLen": f"0x{totalLen:04X}",
        "identification": f"0x{identification:04X}",
        "flags": f"0x{flags:X}",
        "fragOffset": f"0x{fragOffset:04X}",
        "ttl": ttl,
        "protocol": protocol,
        "hdrChecksum": f"0x{hdrChecksum:04X}",
        "srcAddr": srcAddr,
        "dstAddr": dstAddr
    }
    return parsed, offset + 20

def parse_icmp(packet, offset):
    type_ = packet[offset]
    code = packet[offset+1]
    checksum = int.from_bytes(packet[offset+2:offset+4], 'big')
    restOfHeader = int.from_bytes(packet[offset+4:offset+8], 'big')
    parsed = {
        "type": type_,
        "code": code,
        "checksum": f"0x{checksum:04X}",
        "restOfHeader": f"0x{restOfHeader:08X}"
    }
    return parsed, offset + 8

def parse_udp(packet, offset):
    srcPort = int.from_bytes(packet[offset:offset+2], 'big')
    dstPort = int.from_bytes(packet[offset+2:offset+4], 'big')
    length = int.from_bytes(packet[offset+4:offset+6], 'big')
    checksum = int.from_bytes(packet[offset+6:offset+8], 'big')
    parsed = {
        "srcPort": srcPort,
        "dstPort": dstPort,
        "length": f"0x{length:04X}",
        "checksum": f"0x{checksum:04X}"
    }
    return parsed, offset + 8

def parse_tcp(packet, offset):
    srcPort = int.from_bytes(packet[offset:offset+2], 'big')
    dstPort = int.from_bytes(packet[offset+2:offset+4], 'big')
    seqNo = int.from_bytes(packet[offset+4:offset+8], 'big')
    ackNo = int.from_bytes(packet[offset+8:offset+12], 'big')
    dataOffset = (packet[offset+12] >> 4) & 0xF
    reserved = (packet[offset+12] & 0x0E) >> 1
    flags = ((packet[offset+12] & 0x01) << 8) | packet[offset+13]
    window = int.from_bytes(packet[offset+14:offset+16], 'big')
    checksum = int.from_bytes(packet[offset+16:offset+18], 'big')
    urgentPtr = int.from_bytes(packet[offset+18:offset+20], 'big')

    parsed = {
        "srcPort": srcPort,
        "dstPort": dstPort,
        "seqNo": f"0x{seqNo:08X}",
        "ackNo": f"0x{ackNo:08X}",
        "dataOffset": dataOffset,
        "reserved": reserved,
        "flags": f"0x{flags:03X}",
        "window": f"0x{window:04X}",
        "checksum": f"0x{checksum:04X}",
        "urgentPtr": f"0x{urgentPtr:04X}"
    }
    return parsed, offset + 20



offset = 0
type = 'ethernet'
while True:
    if type == 'ethernet':
        eth_hdr, offset = parse_ethernet(data, offset)
        print("Ethernet Header:", eth_hdr)
        if eth_hdr["ethertype"] != "0x88b5":
            parse_type = "default"
        match parse_type:
            case "parse_icmp" | "parse_udp" | "parse_tcp":
                type = 'custom_t'
            case _:
                type = 'custom_t' if eth_hdr["ethertype"] == "0x88b5" else 'ipv4'
    elif type == 'custom_t':
        custom_hdr, offset = parse_custom_t(data, offset)
        print("Custom Header:", custom_hdr)
        match parse_type:
            case "parse_icmp" | "parse_udp" | "parse_tcp":
                type = 'ipv4'
            case _:
                type = 'ipv4' if custom_hdr["etherType"] == "0x0800" else ''
    elif type == 'ipv4':
        ipv4_hdr, offset = parse_ipv4_fixed(data, offset)
        print("IPv4 Header:", ipv4_hdr)
        match parse_type:
            case "parse_icmp":
                type = 'icmp'
            case "parse_udp":
                type = 'udp'
            case "parse_tcp":
                type = 'tcp'
            case _:
                match ipv4_hdr["protocol"]:
                    case 1:
                        type = 'icmp'
                    case 6:
                        type = 'tcp'
                    case 17:
                        type = 'udp'
                    case _:
                        type = ''
    elif type == 'icmp':
        icmp_hdr, offset = parse_icmp(data, offset)
        print("ICMP Header:", icmp_hdr)
        type = ''
    elif type == 'udp':
        udp_hdr, offset = parse_udp(data, offset)
        print("UDP Header:", udp_hdr)
        type = ''
    elif type == 'tcp':
        tcp_hdr, offset = parse_tcp(data, offset)
        print("TCP Header:", tcp_hdr)
        type = ''
    else:
        break

payload = data[offset:]
print("Payload length:", len(payload))
print()
