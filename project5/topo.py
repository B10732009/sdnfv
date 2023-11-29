from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # Add hosts
        h1 = self.addHost('h1', ip='192.168.0.1/27', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='192.168.0.2/27', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='192.168.0.3/27', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='192.168.0.4/27', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='192.168.0.5/27', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='192.168.0.6/27', mac='00:00:00:00:00:06')
        h7 = self.addHost('h7', ip='192.168.0.7/27', mac='00:00:00:00:00:07')
        h8 = self.addHost('h8', ip='192.168.0.8/27', mac='00:00:00:00:00:08')
        h9 = self.addHost('h9', ip='192.168.0.9/27', mac='00:00:00:00:00:09')

        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Add links
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)

        self.addLink(s2, h1)
        self.addLink(s2, h2)
        self.addLink(s2, h3)

        self.addLink(s3, h4)
        self.addLink(s3, h5)
        self.addLink(s3, h6)

        self.addLink(s4, h7)
        self.addLink(s4, h8)
        self.addLink(s4, h9)


topos = { 'MyTopo': MyTopo }