#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet, ethernet, ipv4


logger = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class AdaptiveSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MIRROR_PORT = 25

    def __init__(self, *args, **kwargs):
        logger.info("method AdaptiveSwitch.__init__")
        super(AdaptiveSwitch, self).__init__(*args, **kwargs)
        self.datapath_list = {}
        self.mac_to_port = {}

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        logger.info("method AdaptiveSwitch._state_change_handler datapath = %16d" % ev.datapath.id)
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list:
                logger.debug('register datapath: %16x', datapath.id)
                self.datapath_list[datapath.id] = datapath
                self.mac_to_port[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                logger.debug('unregister datapath: %16x', datapath.id)
                del self.datapath_list[datapath.id]
                del self.mac_to_port[datapath.id]

    #switch init
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_empty = parser.OFPMatch()
        actions = [parser.OFPActionOutput(self.MIRROR_PORT)]
        for i in range(0, 3):
            inst = [parser.OFPInstructionGotoTable(i + 1),
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, i, 0, match_empty, inst)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 3, 0, match_empty, inst)

    #packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        #        if eth:
        #            print "type(eth)=", type(eth)
        #            print "eth=", eth
        #            print "eth.src=", eth.src
        #            print "eth.dst=", eth.dst
        #        else:
        #            print "not eth type"
        src = eth.src
        dst = eth.dst
        self.mac_list[datapath.id].append(src)
        self.mac_list[datapath.id].append(dst)

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            print type(pkt_ipv4)
            print pkt_ipv4
            print pkt_ipv4.src
            print pkt_ipv4.dst
            self.ip_list[datapath.id].append(pkt_ipv4.src)
            self.ip_list[datapath.id].append(pkt_ipv4.dst)
        else:
            print "not ipv4 type"
        #        print "pkt_ipv4 = ", utils.to_dict(pkt_ipv4)

        logger.debug("packet in %s %s %s %s", datapath.id, src, dst, in_port)

        self.mac_to_port[datapath.id][src] = in_port

        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 2, 2, match, inst)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)

    #add flow
    #TODO add timeout params for monitor.
    @staticmethod
    def add_flow(datapath, table_id, priority, match, inst):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, idle_timeout=0, hard_timeout=0, priority=priority,
                                flags=ofproto_v1_3.OFPFF_CHECK_OVERLAP, match=match, instructions=inst)
        datapath.send_msg(mod)

    #delete flow
    #TODO add the table_id and so on? In case of similar entry in different table
    @staticmethod
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)