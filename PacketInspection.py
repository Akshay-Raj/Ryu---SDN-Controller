from ryu.base import app_manager

# importing the v1.3 protocol of openflow
from ryu.ofproto import ofproto_v1_3
# importing the packet for packet extaction and inspection
from ryu.lib.packet import packet
# importing ofp_event handler to processs the queuing and dequeing process and as to how each event is handled
from ryu.controller import ofp_event
# importing the config dispatcher for configuaration negotiation and main dispatcher as to how the packets to be routed
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# importing the set_ecent_class decarator
from ryu.controller.handler import set_ev_cls
import array
# importing the ethernet packet for analysing source and destination mac address and manipulating it for static routing
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
# importing ipv4 and tcp protocols from the packet library for packet inspection and handshake inspection
from ryu.lib.packet import ipv4, tcp


class SimpleSwitch13(app_manager.RyuApp):
	#using protocol v1.3 of openflow
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #using args and kwargs to denaote some unspecified variabes to go in as input into the simpleswitch13 class
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
     # using the set_event_class decorator for negoatiating the onfig dispatcher messages such as to what version of protocol(Openflow v1.3)   
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_handler_rules(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.flow_add_rule(datapath, 0, match, actions)
        #adding the flow for the configuration message
    def flow_add_rule(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        #checking the buffer_id of the packet
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
     #Using the main_dispatcherfor adding the flow rules to the data plane region
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        #printing the message data in raw format which is the similar byte array format that we see in wireshark
        print("msg.data: ", ev.msg.data)
        pkt = packet.Packet(ev.msg.data)
        for p in pkt.protocols:
            print(p.protocol_name, p)
            if p.protocol_name == 'ipv4':
                print('IP: src {} dst {}'.format(p.src, p.dst))
                #printing the source and destination ip address 

        # Imported the code from the ryu documentation example of simple switch 13 for packet handling
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # in_port is the inpuut port from which a packet is entering a switch/router in the data plane region
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Eliination the usage of LLDP packets.
            return
        dst = eth.dst
        src = eth.src
        #dpid refers to the switch id for each switch in the dataplane region
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #logging/printing the datafor the souce and destination of ;ayer to address such as mac and ports
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        #checking whether the destinatin address is in the flow table 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
        	#if no match found telling the flood the ping packets to find the path 
            out_port = ofproto.OFPP_FLOOD
        # Telling to perform the specific action
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.flow_add_rule(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.flow_add_rule(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

