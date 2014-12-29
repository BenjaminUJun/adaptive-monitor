#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import logging
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet, ethernet, ipv4


class AdaptiveSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MIRROR_PORT = 25

    def __init__(self, *args, **kwargs):
        logging.log(logging.INFO, "[INFO %s] AdaptiveSwitch__init__" % time.strftime("%Y-%m-%d %H:%M:%S"))
        super(AdaptiveSwitch, self).__init__(*args, **kwargs)
        self.datapath_list = {}
        self.mac_to_port = {}

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        logging.log(logging.INFO, "[INFO %s] AdaptiveSwitch._state_change_handler Datapath %x" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), ev.datapath.id))
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list:
                logging.log(logging.INFO,
                            "[INFO %s] AdaptiveSwitch._state_change_handler Register Datapath %x" % (
                                time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
                self.datapath_list[datapath.id] = datapath
                self.mac_to_port[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                logging.log(logging.INFO,
                            "[INFO %s] AdaptiveSwitch._state_change_handler Unregister Datapath %16d" % (
                                time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
                del self.datapath_list[datapath.id]
                del self.mac_to_port[datapath.id]

    #switch init
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        logging.log(logging.INFO,
                    "[INFO %s] AdaptiveSwitch._switch_features_handler Datapath %16d" % ev.msg.datapath.id)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match_empty = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
                  parser.OFPActionOutput(self.MIRROR_PORT)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, action)]
        self.add_flow(datapath, 0, match_empty, inst)

    #packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        logging.log(logging.INFO,
                    "[INFO %s] AdaptiveSwitch._packet_in_handler Datapath %x" % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), ev.msg.datapath.id))
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        logging.log(logging.DEBUG,
                    "[DEBUG %s] AdaptiveSwitch._packet_in_handler Msg %s" % (
                        time.strftime("%Y-%m-%d %H:%M:%S"), str(msg)))
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_eth:
            src_eth = pkt_eth.src
            dst_eth = pkt_eth.dst

        logging.log(logging.INFO, "[INFO %s] packet_eth in %d %s %s %d" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id, src_eth, dst_eth, in_port))

        self.mac_to_port[datapath.id][src_eth] = in_port

        if dst_eth in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst_eth]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                parser.OFPActionOutput(self.MIRROR_PORT)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_eth)
            self.add_flow(datapath, 2, match, inst)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)

    #add flow
    #TODO add timeout params for monitor.
    @staticmethod
    def add_flow(datapath, priority, match, inst):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=0, hard_timeout=0, priority=priority,
                                flags=ofproto_v1_3.OFPFF_CHECK_OVERLAP, match=match, instructions=inst)
        datapath.send_msg(mod)

    #delete flow
    @staticmethod
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)