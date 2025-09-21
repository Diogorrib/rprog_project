# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.core import core
import pox.openflow.libopenflow_01 as of
import random

log = core.getLogger()

IDLE_TIMEOUT = 10
HARD_TIMEOUT = 30

FAST_TO_SLOW_RATIO = 2
SLOW_PATH = [1, 2, 3, 6]
FAST_PATH = [1, 4, 5, 6]

EDGE_SWITCHES = {1, 6}
CORE_SWITCHES = {2, 3, 4, 5}

topology_links = { # dpid1, port1, dpid2, port2
  (1,2,2,1),
  (2,2,3,1),
  (3,2,6,1),
  (1,3,4,1),
  (4,2,5,1),
  (5,2,6,2)
}

neighbor_to_port_map = {}
port_to_neighbor_map = {}
switches = {}

flow_cookies = { "fast": set(), "slow": set() }

curr_cookie = 0
def alloc_cookie():
    global curr_cookie
    curr_cookie += 1
    return curr_cookie


def install_flow_across_path (path, packet, packet_in, curr_index, cookie):
  """ Installs flow entries across the given path. """
  curr_dpid = path[curr_index] # save the switch DPID that sent the packet_in
  if curr_index != 0:
    path = list(reversed(path))

  # Install flow in one way but reverse order to avoid flow table misses in the following switches
  for dpid in reversed(path):
    switch = switches[dpid]

    i = path.index(dpid)
    in_port = packet_in.in_port if i == 0 else switch.get_port(path[i - 1])
    out_port = switch.mac_to_port.get(packet.dst) if i == len(path) - 1 else switch.get_port(path[i + 1])

    if not in_port or not out_port:
      log.warning("Cannot install flow on switch %s: missing port info" % dpid)
      continue # this will lead to flow table miss on the switch

    c = cookie if dpid == curr_dpid else None
    switch.install_flow(packet, packet_in, in_port, out_port, cookie=c)


class SwitchHandler (object):
  """
  A SwitchHandler object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    self.connection = connection
    self.dpid = connection.dpid

    connection.addListeners(self)
    switches[self.dpid] = self

    self.mac_to_port = {}


  def get_neighbor (self, port):
    """ Utility to get the neighbor switch on a given port. """
    return port_to_neighbor_map[self.dpid].get(port)


  def get_port (self, dpid):
    """ Utility to get the port number for a given neighbor switch. """
    return neighbor_to_port_map[self.dpid].get(dpid)


  def resend_packets (self, packet_in, out_ports):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to us.
    "out_ports" is a list of ports to send the packet out on.
    """
    msg = of.ofp_packet_out()
    msg.in_port = packet_in.in_port
    msg.buffer_id = None
    msg.data = packet_in.data

    for p in out_ports:
      log.debug("  sending packet out port %s" % (p,))
      msg.actions.append(of.ofp_action_output(port = p))
    self.connection.send(msg)


  def learn_mac (self, mac, port):
    self.mac_to_port[mac] = port


  def forward_packet (self, packet, packet_in, out_port):
    pass # abstract - to be implemented in subclasses


  def install_flow (self, packet, packet_in, in_port, out_port, require_data=False, cookie=None):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, in_port)

    log.debug("Installing flow on switch %s: %s.%i -> %s.%i" % (
      self.dpid, packet.src, in_port, packet.dst, out_port))

    msg.idle_timeout = IDLE_TIMEOUT
    msg.hard_timeout = HARD_TIMEOUT
    if cookie:
      msg.cookie = cookie
      msg.flags = of.OFPFF_SEND_FLOW_REM

    if not require_data and not cookie:
      msg.buffer_id = None
    elif packet_in.buffer_id is not None and packet_in.buffer_id != -1:
      msg.buffer_id = packet_in.buffer_id 
    else:
      msg.data = packet_in

    msg.actions.append(of.ofp_action_output(port=out_port))
    self.connection.send(msg)


  def _handle_PacketIn (self, event):
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.learn_mac(packet.src, packet_in.in_port)

    out_port = self.mac_to_port.get(packet.dst)
    if out_port and out_port != -1:
      # this flow is not in any path or was not installed since the switch didn't know the dst MAC
      self.install_flow(packet, packet_in, packet_in.in_port, out_port, require_data=True)
      return

    log.debug("Switch %s: Received %s.%i -> %s on port %s" % (self.dpid,
                packet.src, packet_in.in_port, packet.dst, packet_in.in_port))
    self.forward_packet(packet, packet_in, out_port)


  def _handle_FlowRemoved (self, event):
    cookie = event.ofp.cookie
    flow_cookies["fast"].discard(cookie)
    flow_cookies["slow"].discard(cookie)

    log.debug("Flow with COOKIE %s REMOVED from switch %s" % (cookie, self.dpid))
    log.debug("  Remaining flows: FAST %d | SLOW %d" % (len(flow_cookies["fast"]), len(flow_cookies["slow"])))


class EdgeSwitchHandler (SwitchHandler):
  """
  Edge switches are the ones connected to hosts.
  """
  def flood (self, packet_in, next_hop=None):
    """ Floods the packet out all ports except the input port and
        neighboring switches (unless next_hop is specified). """
    neighbor_ports = set(port_to_neighbor_map[self.dpid].keys())
    ports_to_flood = []
    for p, _ in self.connection.ports.iteritems():
      if p == packet_in.in_port: continue
      if p <= 0 or p > of.OFPP_MAX: continue
      if (not next_hop or p != next_hop) and p in neighbor_ports: continue
      ports_to_flood.append(p)

    self.resend_packets(packet_in, ports_to_flood)


  def learn_mac (self, mac, port):
    if port in port_to_neighbor_map[self.dpid]:
      self.mac_to_port[mac] = -1 # MAC is on a neighboring switch thus it can follow 2 different paths for QoS
    else:
      super(EdgeSwitchHandler, self).learn_mac(mac, port) # MAC is on a host thus it can follow only one path


  def get_next_hop (self, path):
    """ Utility to get the next hop switch's port number for a given path. """
    curr_index = path.index(self.dpid)
    next_hop = path[curr_index + 1] if curr_index == 0 else path[curr_index - 1]
    return self.get_port(next_hop)


  def choose_path (self):
    cookie = alloc_cookie()
    if len(flow_cookies["fast"]) <= FAST_TO_SLOW_RATIO * len(flow_cookies["slow"]):
      flow_cookies["fast"].add(cookie)
      log.debug("Installing flow with COOKIE %s across FAST path" % cookie)
      return FAST_PATH, cookie
    flow_cookies["slow"].add(cookie)
    log.debug("Installing flow with COOKIE %s across SLOW path" % cookie)
    return SLOW_PATH, cookie


  def forward_packet (self, packet, packet_in, out_port):
    if not out_port: # generalized to unknown port (not only ARP) - old version below
    #if packet.type == packet.ARP_TYPE and packet.payload.opcode == packet.payload.REQUEST:
      # If the ARP request came from a switch, flood it to hosts only
      if self.get_neighbor(packet_in.in_port):
        self.flood(packet_in)
        return

      # Otherwise, send it along the probabilistic path and flood to hosts
      path = FAST_PATH if random.random() < 2/3 else SLOW_PATH
      self.flood(packet_in, self.get_next_hop(path))
    else: # port is -1 i.e. known but can follow 2 paths
      path, cookie = self.choose_path()
      install_flow_across_path(path, packet, packet_in, path.index(self.dpid), cookie)


class CoreSwitchHandler (SwitchHandler):
  """
  Core switches are the ones in the middle of the network.
  They are not connected to any hosts.
  """
  def flood (self, packet_in):
    """ Normal flooding given absence of loops in core. """
    self.resend_packets(packet_in, (of.OFPP_FLOOD,))


  def forward_packet (self, packet, packet_in, out_port):
    self.flood(packet_in)



def launch ():

  def add_link (s1, p1, s2, p2):
    """
    Add a link to the neighbor/port maps.
    """
    neighbor_to_port_map.setdefault(s1, {})[s2] = p1
    neighbor_to_port_map.setdefault(s2, {})[s1] = p2
    port_to_neighbor_map.setdefault(s1, {})[p1] = s2
    port_to_neighbor_map.setdefault(s2, {})[p2] = s1

  def start_switch (event):
    log.debug("Switch %s has come up." % event.dpid)
    if event.dpid in EDGE_SWITCHES:
      EdgeSwitchHandler(event.connection)
    else:
      CoreSwitchHandler(event.connection)

  for (s1, p1, s2, p2) in topology_links:
    add_link(s1, p1, s2, p2)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
