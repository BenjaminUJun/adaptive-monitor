#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

import utils


class AdaptiveSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    MIRROR_PORT = 25

    def __init__(self, *args, **kwargs):

        self.logger = logging.getLogger()
        formatter = logging.Formatter('[%(levelname)s %(asctime)s] IIIS %(name)s.%(funcName)s %(message)s',
                                      '%Y%m%d %H:%M:%S')
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        self.logger.addHandler(console)

        self.logger.info("")
        super(AdaptiveSwitch, self).__init__(*args, **kwargs)
        self.datapath_list = {}
        self.ip_to_mac = {}
        self.mac_to_port = {}

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        self.logger.info("method AdaptiveSwitch._state_change_handler datapath = %16d" % ev.datapath.id)
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list:
                self.logger.debug('register datapath: %16x', datapath.id)
                self.datapath_list[datapath.id] = datapath
                self.mac_to_port[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                self.logger.debug('unregister datapath: %16x', datapath.id)
                del self.datapath_list[datapath.id]
                del self.mac_to_port[datapath.id]

    #switch init
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        self.logger.info("method AdaptiveSwitch._switch_features_handler datapath = %16d" % ev.msg.datapath.id)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(1)]
        match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src='10.3.0.123', ipv4_dst='10.3.0.124')
        inst = [parser.OFPInstructionGotoTable(1), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        #        self.add_flow(datapath, 0, 5, match_ip, inst)

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
        self.logger.info("method AdaptiveSwitch._packet_in_handler datapath = %16d" % ev.msg.datapath.id)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_eth:
            src_eth = pkt_eth.src
            dst_eth = pkt_eth.dst

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst

        self.logger.info("packet_eth in %d %s %s %d" % (datapath.id, src_eth, dst_eth, in_port))
        self.logger.info("packet_ip in %d %s %s %d" % (datapath.id, src_ip, dst_ip, in_port))

        self.mac_to_port[datapath.id][src_eth] = in_port
        self.ip_to_mac[datapath.id][src_ip] = src_eth

        if dst_eth in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst_eth]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#        inst += mirrorport

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_eth)
            print "datapath.id = ",
            print datapath.id
            print "match = ",
            print utils.to_string(match)
            print "inst = ",
            print utils.to_string(inst)
            self.add_flow(datapath, 3, 2, match, inst)

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

    #delete flow
    #TODO add the table_id and so on? In case of similar entry in different table
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)