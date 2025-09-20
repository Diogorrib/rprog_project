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

log = core.getLogger()

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


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to us.
    """
    msg = of.ofp_packet_out()
    msg.in_port = packet_in.in_port
    msg.buffer_id = of.NO_BUFFER
    msg.data = packet_in.data

    log.debug("  sending packet out port %s" % (out_port,))
    msg.actions.append(of.ofp_action_output(port = out_port))
    self.connection.send(msg)


  def forward_packet (self, packet, packet_in):
    pass # abstract - to be implemented in subclasses


  def _handle_PacketIn (self, event):
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.mac_to_port[packet.src] = packet_in.in_port # FIXME - sometimes mac can be in 2 ports (edge switch)

    if self.mac_to_port.get(packet.dst):
      log.debug("Switch %s: Forwarding %s.%i -> %s.%i" % (self.dpid,
                  packet.src, packet_in.in_port, packet.dst,
                  self.mac_to_port[packet.dst]))
      self.resend_packet(packet_in, self.mac_to_port[packet.dst])
      return

    self.forward_packet(packet, packet_in)


class EdgeSwitchHandler (SwitchHandler):
  """
  Edge switches are the ones connected to hosts.
  """
  def flood (self, packet_in, next_hop=None):
    """ Floods the packet out all ports except the input port and
        neighboring switches (unless next_hop is specified). """
    neighbor_ports = set(port_to_neighbor_map[self.dpid].keys())
    for p, _ in self.connection.ports.iteritems():
      if p == packet_in.in_port: continue
      if p <= 0 or p > of.OFPP_MAX: continue
      if (not next_hop or p != next_hop) and p in neighbor_ports: continue

      log.debug("  flooding ARP request on port %s" % (p,))
      self.resend_packet(packet_in, p)


  def forward_packet (self, packet, packet_in):
    if packet.type == packet.ARP_TYPE:
      path = FAST_PATH
      log.debug("Switch %s: ARP %s: %s -> %s on port %s from %s" % (
          self.dpid, "request" if packet.payload.opcode==1 else "reply",
          packet.src, packet.dst, packet_in.in_port,
          self.get_neighbor(packet_in.in_port)))

      # If the ARP came from a switch, flood it to hosts only
      if self.get_neighbor(packet_in.in_port):
        self.flood(packet_in)
        return

      # Otherwise, send it along the path while also flooding it to hosts
      curr_index = path.index(self.dpid)
      next_hop = path[curr_index + 1] if curr_index == 0 else path[curr_index - 1]
      self.flood(packet_in, self.get_port(next_hop))
    else:
      log.debug("WHAT DO I DO WITH THIS NON-ARP PACKET?!?!")


class CoreSwitchHandler (SwitchHandler):
  """
  Core switches are the ones in the middle of the network.
  They are not connected to any hosts.
  """
  def flood (self, packet_in):
    """ Normal flooding given absence of loops in core. """
    self.resend_packet(packet_in, of.OFPP_FLOOD)


  def forward_packet (self, packet, packet_in):
    if packet.type == packet.ARP_TYPE:
      path = FAST_PATH
      log.debug("Switch %s: ARP %s: %s -> %s on port %s from %s" % (
          self.dpid, "request" if packet.payload.opcode==1 else "reply",
          packet.src, packet.dst, packet_in.in_port,
          self.get_neighbor(packet_in.in_port)))

      """ prev = self.get_neighbor(packet_in.in_port)
      prev_index = path.index(prev) if prev else None
      curr_index = path.index(self.dpid)

      next_hop = path[curr_index + 1] if prev_index < curr_index else path[curr_index - 1]
      out_port = self.get_port(next_hop)
      self.resend_packet(packet_in, out_port) """

      # One entry and one exit - just flood
      self.flood(packet_in)

    else:
      log.debug("WHAT DO I DO WITH THIS NON-ARP PACKET?!?!")



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
