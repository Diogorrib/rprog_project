#!/usr/bin/env python3
import argparse
import os
import sys
import time

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

import cli_helper
import seed_handler
import random

global_links = []   # list of tuples (src_sw, dst_sw, src_index, dst_index)
update_times = []   # time intervals for each link to update seeds
update_state = []   # last update time for each link
update_pending = [] # pending second phase of the update

def writeL2ForwardingRule(p4info_helper, sw, dst_eth_addr, port):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param dst_eth_addr: the destination Ethernet address to write in the packet
    :param port: the port to forward the packet out of 
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.mac_exact",
        match_fields={
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name="MyIngress.forward",
        action_params={
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed L2 forwarding rule to %s on %s" % (dst_eth_addr, sw.name))


def createMulticastGroups(p4info_helper, sw, port_list):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param port_list: a list of all ports connecting to hosts
    """
    for i in range(len(port_list)):
        
        replicas = [
            {'egress_port': p, 'instance': 0}
            for p in port_list if p != port_list[i]
        ]
        mc_group_entry = p4info_helper.buildMulticastGroupEntry(
            multicast_group_id=port_list[i],
            replicas=replicas
        )
        sw.WritePREEntry(mc_group_entry)
        print("Installed multicast group %d on %s" % (port_list[i], sw.name))


def writeL3ForwardingRule(p4info_helper, sw, type, dst_ip_addr,
                          dst_eth_addr, src_eth_addr, port):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param type: the type of match ("exact" or "lpm")
    :param dst_ip_addr: the destination IP address to match
    :param dst_eth_addr: the destination Ethernet address to write in the packet
    :param src_eth_addr: the source Ethernet address to write in the packet
    :param port: the port to forward the packet out of
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_%s" % type,
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "srcAddr": src_eth_addr,
            "dstAddr": dst_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed L3 forwarding rule to %s on %s" % (dst_ip_addr, sw.name))


def writeL3ReversePathRule(p4info_helper, sw, dst_ip_addr, src_ip_addr,
                           dst_eth_addr, src_eth_addr, port):
    """
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    :param dst_ip_addr: the destination IP address to match
    :param dst_eth_addr: the destination Ethernet address to write in the packet
    :param src_ip_addr: the source IP address to match (used for reverse paths)
    :param src_eth_addr: the source Ethernet address to write in the packet
    :param port: the port to forward the packet out of
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_reverse",
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr,
            "hdr.ipv4.srcAddr": src_ip_addr
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "srcAddr": src_eth_addr,
            "dstAddr": dst_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print("Installed L3 forwarding rule to %s on %s" % (dst_ip_addr, sw.name))


def writeAllForwardingRules(p4info_helper_sw, p4info_helper_router, sw_list, router_list):
    s1, s2 = sw_list
    r1, r2, r3, r4, r5 = router_list

    # Write forwarding rules for s1
    writeL2ForwardingRule(p4info_helper_sw, sw=s1, dst_eth_addr="08:00:00:00:01:11", port=1)
    writeL2ForwardingRule(p4info_helper_sw, sw=s1, dst_eth_addr="08:00:00:00:02:22", port=2)
    writeL2ForwardingRule(p4info_helper_sw, sw=s1, dst_eth_addr="08:00:00:00:03:33", port=3)
    writeL2ForwardingRule(p4info_helper_sw, sw=s1, dst_eth_addr="08:00:00:00:aa:aa", port=4)
    createMulticastGroups(p4info_helper_sw, sw=s1, port_list=[1, 2, 3])

    # Write forwarding rules for s2
    writeL2ForwardingRule(p4info_helper_sw, sw=s2, dst_eth_addr="08:00:00:00:04:44", port=1)
    writeL2ForwardingRule(p4info_helper_sw, sw=s2, dst_eth_addr="08:00:00:00:05:55", port=2)
    writeL2ForwardingRule(p4info_helper_sw, sw=s2, dst_eth_addr="08:00:00:00:06:66", port=3)
    writeL2ForwardingRule(p4info_helper_sw, sw=s2, dst_eth_addr="08:00:00:00:bb:bb", port=4)
    createMulticastGroups(p4info_helper_sw, sw=s2, port_list=[1, 2, 3])

    # Write forwarding rules for r1
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.2.4",
                          src_eth_addr="08:00:00:00:aa:11", dst_eth_addr="08:00:00:00:22:11", port=1)
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.2.5",
                          src_eth_addr="08:00:00:00:aa:22", dst_eth_addr="08:00:00:00:33:11", port=2)
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.2.6",
                          src_eth_addr="08:00:00:00:aa:33", dst_eth_addr="08:00:00:00:44:11", port=3)
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.1.1",
                          src_eth_addr="08:00:00:00:aa:aa", dst_eth_addr="08:00:00:00:01:11", port=4)
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.1.2",
                          src_eth_addr="08:00:00:00:aa:aa", dst_eth_addr="08:00:00:00:02:22", port=4)
    writeL3ForwardingRule(p4info_helper_router, sw=r1, type="exact", dst_ip_addr="10.0.1.3",
                          src_eth_addr="08:00:00:00:aa:aa", dst_eth_addr="08:00:00:00:03:33", port=4)

    #Write forwarding rules for r2
    writeL3ForwardingRule(p4info_helper_router, sw=r2, type="lpm", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:22:11", dst_eth_addr="08:00:00:00:aa:11", port=1)
    writeL3ForwardingRule(p4info_helper_router, sw=r2, type="lpm", dst_ip_addr=("10.0.2.0", 24),
                          src_eth_addr="08:00:00:00:22:22", dst_eth_addr="08:00:00:00:bb:11", port=2)

    #Write forwarding rules for r3
    writeL3ForwardingRule(p4info_helper_router, sw=r3, type="lpm", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:33:11", dst_eth_addr="08:00:00:00:aa:22", port=1)
    writeL3ForwardingRule(p4info_helper_router, sw=r3, type="lpm", dst_ip_addr=("10.0.2.0", 24),
                          src_eth_addr="08:00:00:00:33:22", dst_eth_addr="08:00:00:00:bb:22", port=2)

    #Write forwarding rules for r4
    writeL3ForwardingRule(p4info_helper_router, sw=r4, type="lpm", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:44:11", dst_eth_addr="08:00:00:00:aa:33", port=1)
    writeL3ForwardingRule(p4info_helper_router, sw=r4, type="lpm", dst_ip_addr=("10.0.2.0", 24),
                          src_eth_addr="08:00:00:00:44:22", dst_eth_addr="08:00:00:00:bb:33", port=2)

    # Write forwarding rules for r5 (note: reverse paths defined in r1 considering the 10.0.2.x IPs)
    writeL3ReversePathRule(p4info_helper_router, sw=r5, src_ip_addr="10.0.2.4", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:bb:11", dst_eth_addr="08:00:00:00:22:22", port=1)
    writeL3ReversePathRule(p4info_helper_router, sw=r5, src_ip_addr="10.0.2.5", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:bb:22", dst_eth_addr="08:00:00:00:33:22", port=2)
    writeL3ReversePathRule(p4info_helper_router, sw=r5, src_ip_addr="10.0.2.6", dst_ip_addr=("10.0.1.0", 24),
                          src_eth_addr="08:00:00:00:bb:33", dst_eth_addr="08:00:00:00:44:22", port=3)
    writeL3ForwardingRule(p4info_helper_router, sw=r5, type="exact", dst_ip_addr="10.0.2.4",
                          src_eth_addr="08:00:00:00:bb:bb", dst_eth_addr="08:00:00:00:04:44", port=4)
    writeL3ForwardingRule(p4info_helper_router, sw=r5, type="exact", dst_ip_addr="10.0.2.5",
                          src_eth_addr="08:00:00:00:bb:bb", dst_eth_addr="08:00:00:00:05:55", port=4)
    writeL3ForwardingRule(p4info_helper_router, sw=r5, type="exact", dst_ip_addr="10.0.2.6",
                          src_eth_addr="08:00:00:00:bb:bb", dst_eth_addr="08:00:00:00:06:66", port=4)


def writeValueToRegister(p4info_helper, sw, index, val_name, val):
    n_chunks = seed_handler.get_n_chunks(len(val)) if isinstance(val, bytes) else 1
    if n_chunks > 1:
        chunk_size = seed_handler.CHUNK_SIZE
        parts = [val[i:i + chunk_size] for i in range(0, len(val), chunk_size)]
        parts = [seed_handler.seed_to_int(p) for p in parts]
        msg = "Wrote seed %s to register on %s" % (seed_handler.seed_to_hex(val), sw.name)
    else:
        parts = [val]
        msg = "Wrote value %d to register on %s" % (val, sw.name)

    base_index = index * n_chunks
    for i in range(n_chunks):
        cli_helper.register_write(
            thrift_port=sw.thrift_port,
            reg_name="MyIngress.%s" % val_name,
            index=base_index + i,
            value=parts[i]
        )
    #print(msg)


def readValueFromRegister(p4info_helper, sw, index, val_name, n_chunks=1):
    base_index = index * n_chunks
    val_parts = []
    for i in range(n_chunks):
        val = cli_helper.register_read(
            thrift_port=sw.thrift_port,
            reg_name="MyIngress.%s" % val_name,
            index=base_index + i)
        val_parts.append(val)

    if n_chunks > 1:
        val = b''.join([seed_handler.int_to_seed(v) for v in val_parts])
        msg = "Read seed %s from register on %s" % (seed_handler.seed_to_hex(val), sw.name)
    else:
        val = val_parts[0]
        msg = "Read value %d from register on %s" % (val, sw.name)
    #print(msg)
    return val

def compareVersions(p4info_helper, sw, index):
    """Compare the control and current versions to verify if the last update was already applied.
    :return: True if update was performed, False otherwise"""
    ctrl_version = readValueFromRegister(p4info_helper, sw, index, "ctrl_version")
    curr_version = readValueFromRegister(p4info_helper, sw, index, "curr_version")
    return ctrl_version <= curr_version

def extendTimeIfNoUpdate(p4info_helper, link, index, curr_time):
    """If the last update was not yet applied, extend the time to allow seeds to be useful."""
    src, dst, src_index, dst_index = link
    if not compareVersions(p4info_helper, src, src_index) or not compareVersions(p4info_helper, dst, dst_index):
        update_state[index] = curr_time
        print("Previous update not yet applied on link %d, extending time..." % index)
        return True
    return False

def updateLinkSeeds(p4info_helper, link, index, curr_time):
    src, dst, src_index, dst_index = link
    for i in range(2):
        seed = seed_handler.generate_seed()
        writeValueToRegister(p4info_helper, src, src_index*2 + i, "next_seed", seed)
        writeValueToRegister(p4info_helper, dst, dst_index*2 + i, "next_seed", seed)
    update_times[index] = random.randint(25, 35)
    update_state[index] = curr_time
    update_pending[index] = True

def secondPhaseUpdate(p4info_helper, link, index):
    src, dst, src_index, dst_index = link
    curr_version = readValueFromRegister(p4info_helper, src, src_index, "curr_version")
    writeValueToRegister(p4info_helper, src, src_index, "ctrl_version", curr_version + 1)
    writeValueToRegister(p4info_helper, dst, dst_index, "ctrl_version", curr_version + 1)
    update_pending[index] = False

def distributeSeeds(p4info_helper, router_list):
    r1, r2, r3, r4, r5 = router_list
    global_links.append((r1, r2, 0, 0))
    global_links.append((r1, r3, 1, 0))
    global_links.append((r1, r4, 2, 0))
    global_links.append((r2, r5, 1, 0))
    global_links.append((r3, r5, 1, 1))
    global_links.append((r4, r5, 1, 2))

    for (src, dst, src_index, dst_index) in global_links:
        for i in range(2):
            seed = seed_handler.generate_seed()
            #print("Generated seed%d: %s\tfor link %s-%s" % (i+1, seed_handler.seed_to_hex(seed), src.name, dst.name))
            writeValueToRegister(p4info_helper, src, src_index*2 + i, "curr_seed", seed)
            writeValueToRegister(p4info_helper, dst, dst_index*2 + i, "curr_seed", seed)
        writeValueToRegister(p4info_helper, src, src_index, "curr_version", 0)
        writeValueToRegister(p4info_helper, dst, dst_index, "curr_version", 0)
        writeValueToRegister(p4info_helper, src, src_index, "ctrl_version", 0)
        writeValueToRegister(p4info_helper, dst, dst_index, "ctrl_version", 0)

    for sw in router_list:
        seed = seed_handler.generate_seed()
        writeValueToRegister(p4info_helper, sw, 0, "base_prng", seed)
    for _ in range(len(global_links)):
        update_times.append(random.randint(25, 35))
        update_state.append(0)
        update_pending.append(False)


def updateSeeds(p4info_helper, curr_time):
    for i in range(len(global_links)):
        last_update = update_state[i]
        if curr_time - last_update >= update_times[i]:
            if extendTimeIfNoUpdate(p4info_helper, global_links[i], i, curr_time):
                continue
            updateLinkSeeds(p4info_helper, global_links[i], i, curr_time)
            print("First phase of update done for link %d" % i)
        elif update_pending[i]:
            secondPhaseUpdate(p4info_helper, global_links[i], i)
            print("Second phase of update done for link %d" % i)


def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_files, bmv2_files):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper_sw = p4runtime_lib.helper.P4InfoHelper(p4info_files["switch"])
    p4info_helper_router = p4runtime_lib.helper.P4InfoHelper(p4info_files["router"])

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        r1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='r1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/r1-p4runtime-requests.txt')
        r2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='r2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/r2-p4runtime-requests.txt')
        r3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='r3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/r3-p4runtime-requests.txt')
        r4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='r4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/r4-p4runtime-requests.txt')
        r5 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='r5',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/r5-p4runtime-requests.txt')
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50057',
            device_id=6,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        sw_list = [s1, s2]
        router_list = [r1, r2, r3, r4, r5]
        all_devices = sw_list + router_list

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        for d in all_devices:
            d.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        for r in router_list:
            r.SetForwardingPipelineConfig(p4info=p4info_helper_router.p4info,
                                          bmv2_json_file_path=bmv2_files["router"])
            r.thrift_port = 9090 + int(r.name[1:]) - 1
            print("Installed P4 Program using SetForwardingPipelineConfig on %s" % r.name)
        for s in sw_list:
            s.SetForwardingPipelineConfig(p4info=p4info_helper_sw.p4info,
                                          bmv2_json_file_path=bmv2_files["switch"])
            print("Installed P4 Program using SetForwardingPipelineConfig on %s" % s.name)

        # Write forwarding rules
        writeAllForwardingRules(p4info_helper_sw, p4info_helper_router, sw_list, router_list)
        print("Forwarding rules installed.")
        distributeSeeds(p4info_helper_router, router_list)
        print("Initial seeds distributed.")
        print("Ready to forward packets...")
        start_time = int(time.time())

        while True: # p4runtime checks for updates every second
            time.sleep(1)
            curr_time = int(time.time()) - start_time
            updateSeeds(p4info_helper_router, curr_time)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

def createFileDict(dict, path):
    if "switch" in path:
        dict["switch"] = path
    elif "router" in path:
        dict["router"] = path
    else:
        print("\nfile name must contain 'switch' or 'router': %s" % path)
        return False
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='P4Info proto files from p4c',
                        type=str, nargs='+', required=True)
    parser.add_argument('--bmv2-json', help='BMv2 JSON files from p4c',
                        type=str, nargs='+', required=True)
    args = parser.parse_args()

    p4info_files = {}
    bmv2_files = {}
    for path in args.p4info:
        if not os.path.exists(path):
            parser.print_help()
            print("\np4info file not found: %s\nHave you run 'make'?" % path)
            parser.exit(1)
        if not createFileDict(p4info_files, path):
            parser.exit(1)
    for path in args.bmv2_json:
        if not os.path.exists(path):
            parser.print_help()
            print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % path)
            parser.exit(1)
        if not createFileDict(bmv2_files, path):
            parser.exit(1)
    main(p4info_files, bmv2_files)
