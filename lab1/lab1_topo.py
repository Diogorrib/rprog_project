"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        hosts = {}
        switches = {}
        for i in range(1, 7):
            hosts[i] = self.addHost('h%d' % i)
            switches[i] = self.addSwitch('s%d' % i)

        # Add links
        self.addLink(hosts[1],    switches[1])
        self.addLink(switches[1], switches[2], cls=TCLink, bw=500)
        self.addLink(switches[2], switches[3], cls=TCLink, bw=500)
        self.addLink(switches[3], switches[6], cls=TCLink, bw=500)
        self.addLink(switches[1], switches[4], cls=TCLink, bw=1000)
        self.addLink(switches[4], switches[5], cls=TCLink, bw=1000)
        self.addLink(switches[5], switches[6], cls=TCLink, bw=1000)
        self.addLink(switches[6], hosts[2])
        self.addLink(switches[6], hosts[3])
        self.addLink(switches[6], hosts[4])
        self.addLink(switches[6], hosts[5])
        self.addLink(switches[6], hosts[6])


topos = { 'mytopo': ( lambda: MyTopo() ) }
