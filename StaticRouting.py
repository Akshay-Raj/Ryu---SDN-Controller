from ryu.base import app_manager

# importing ofp_event handler to processs the queuing and dequeing process and as to how each event is handled
from ryu.controller import ofp_event
# importing the config dispatcher for configuaration negotiation and main dispatcher as to how the packets to be routed
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# importing the set_ecent_class decarator
from ryu.controller.handler import set_ev_cls
# importing the v1.3 protocol of openflow
from ryu.ofproto import ofproto_v1_3
# importing the packet for packet extaction and inspection
from ryu.lib.packet import packet
# importing the ethernet packet for analysing source and destination mac address and manipulating it for static routing
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


from ryu.ofproto import ether
# importing ipv4 and tcp protocols from the packet library for packet inspection and handshake inspection
from ryu.lib.packet import ipv4, arp


class StaticRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(StaticRouting, self).__init__(*args, **kwargs)
        # MAC Addresses are not spoofed instead it'll be changed in the middlle of the path
        self.s1_gateway_mac = '00:00:00:00:00:10'  # Gateway-1 MAC address
        self.s2_gateway_mac = '00:00:00:00:00:20'  # Gateway-2 MAC address
        self.s2_gateway_mac = '00:00:00:00:00:30'  # Gateway-3 MAC address

# Decorator which initiates the Switch feature event during the initial setup of the switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # extract the defapath features
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the default table-miss flow entry with priority 0
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install static flow rule swith priority 1
        # match based on in_port, IP source, IP dest
        
        # For Datapath 1 (switch 1)
        if datapath.id == 1:
            # flow from h1 to h2
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.1.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.2.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h1-h2**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # flow from h1 to h2 to h3
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.1.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.3.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h1-h3 via h2**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # flow from h2 to h1
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.2.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.1.0', '255.255.255.0'))
            out_port = 1
            print('**********Installing flow for h2-h1**********')
            # changing the MAC address of the destination (Host 1) in the middle of the path before installing the rule
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

            # flow from h3 to h2 to h1
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.3.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.1.0', '255.255.255.0'))
            out_port = 1
            print('**********Installing flow for h3-h1 via h2**********')
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:01"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

        # For Datapath 2 (Switch-2)
        if datapath.id == 2:
            # flow from h1 to h2
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.1.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.2.0', '255.255.255.0'))
            out_port = 1
            # Can rewrite dst mac to h2 or spoof like we have done
            print('**********Installing flow for h1-h2**********')
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # flow from h1 to h2 to h3
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.1.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.3.0', '255.255.255.0'))
            out_port = 3
            print('**********Installing flow for h1-h3 via h2**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # from from h2 to h1
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.2.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.1.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h2-h1**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # from from h2 to h3
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.2.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.3.0', '255.255.255.0'))
            out_port = 3
            print('**********Installing flow for h2-h3**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # flow from h3 to h2 to h1
            match = parser.OFPMatch(in_port=3,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.3.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.1.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h3-h2 via h1**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

            # from from h3 to h2
            match = parser.OFPMatch(in_port=3,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.3.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.2.0', '255.255.255.0'))
            out_port = 1
            print('**********Installing flow for h3-h2**********')
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:02"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

        # For Datapath 3 (switch-3)
        if datapath.id == 3:
            # flow from h1 to h2 to h3
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.1.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.3.0', '255.255.255.0'))
            out_port = 1
            # Can rewrite dst mac to h2 or spoof like we have done
            print('**********Installing flow for h1-h3 via h2**********')
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:03"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


            # flow from h3 to h2 to h1
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.3.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.1.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h3-h1 via h2**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

            # from from h2 to h3
            match = parser.OFPMatch(in_port=2,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.2.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.3.0', '255.255.255.0'))
            out_port = 1
            print('**********Installing flow for h2-h3**********')
            actions = [parser.OFPActionSetField(eth_dst="00:00:00:00:00:03"),parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

            # from from h3 to h2
            match = parser.OFPMatch(in_port=1,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=('192.168.3.0', '255.255.255.0'),
                                    ipv4_dst=('192.168.2.0', '255.255.255.0'))
            out_port = 2
            print('**********Installing flow for h3-h2**********')
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)


# Define the idle and hard time out for aall the flows installed
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # Check for buffer ID and set the timeout to 400 seconds whith the same priority (priority 1)
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=400,
                                    hard_timeout=400)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=400, hard_timeout=400)
            
        #send all the timeout flows to be installed on the switches.
        datapath.send_msg(mod)


# decorator to serve the arp requests from the hosts
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    
    # decoding the openflow event
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        packt = packet.Packet(msg.data)
        eth = packt.get_protocols(ethernet.ethernet)[0]

        # catch the ARP packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_packet = packt.get_protocols(arp.arp)[0]
            ethernet_src = eth.src

            # identify the ip address it is sending the ARP for
            # sendimg the arp response for s2 gateway 192.168.2.1
            if arp_packet.dst_ip == '192.168.2.1' and datapath.id == 2:
                print('Received ARP for 192.168.2.1')

                # generating the arp response packet
                e = ethernet.ethernet(dst=eth.src, src=self.s2_gateway_mac, ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac=self.s2_gateway_mac, src_ip='192.168.2.1',
                            dst_mac=ethernet_src, dst_ip=arp_packet.src_ip)

                # construct an empty packet and add ether and arp packet in it then serialize it 
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                # sending arp response back through the same port where it was received
                outPort = in_port
                actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=p.data)
                datapath.send_msg(out)


            # sendimg the arp response for s3 gateway 192.168.3.1
            elif arp_packet.dst_ip == '192.168.3.1' and datapath.id == 3:
                print('Received ARP for 192.168.3.1')

                # building packet
                e = ethernet.ethernet(dst=eth.src, src=self.s2_gateway_mac, ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac=self.s2_gateway_mac, src_ip='192.168.3.1',
                            dst_mac=ethernet_src, dst_ip=arp_packet.src_ip)

                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                # sending arp response back through the same port where it was received
                outPort = in_port
                actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, # since theere is no actual input port
                    actions=actions,
                    data=p.data)
                datapath.send_msg(out)



            # sendimg the arp response for s1 gateway 192.168.1.1
            elif arp_packet.dst_ip == '192.168.1.1' and datapath.id == 1:
                print('Received ARP for 192.168.1.1')

                # building packet
                e = ethernet.ethernet(dst=eth.src, src=self.s1_gateway_mac, ethertype=ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                            src_mac=self.s1_gateway_mac, src_ip='192.168.1.1',
                            dst_mac=ethernet_src, dst_ip=arp_packet.src_ip)

                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                p.serialize()

                # sending arp response back through the same port where it was received
                outPort = in_port
                actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=0xffffffff,
                    in_port=datapath.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=p.data)
                datapath.send_msg(out)

        # verbosely decoding all the arp and IP packets and priting its content
        try:
            for p in packt.protocols:
                print(p.protocol_name, p)
            print("datapath: {} in_port: {}".format(datapath.id, in_port))
        except:
            pass



