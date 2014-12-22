#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

MTN = 0

class TableDelayTest(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        self.datapath_list = {}
        self.mac_to_port = {}

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list:
                self.datapath_list[datapath.id] = datapath
                self.mac_to_port[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                del self.datapath_list[datapath.id]
                del self.mac_to_port[datapath.id]

    #switch init
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_empty = parser.OFPMatch()
        actions = [parser.OFPActionOutput(self.MIRROR_PORT)]
        for i in range(0, MTN):
            inst = [parser.OFPInstructionGotoTable(i + 1),
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.add_flow(datapath, i, 0, match_empty, inst)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, MTN, 0, match_empty, inst)

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
        src = eth.src
        dst = eth.dst

        self.mac_to_port[datapath.id][src] = in_port

        if dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, MTN, 2, match, inst)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)

    #add flow
    #TODO add timeout params for monitor.
    def add_flow(self, datapath, table_id, priority, match, inst):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, idle_timeout=0, hard_timeout=0, priority=priority,
                                flags=ofproto_v1_3.OFPFF_CHECK_OVERLAP, match=match, instructions=inst)
        datapath.send_msg(mod)