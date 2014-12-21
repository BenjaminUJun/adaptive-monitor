#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-


from operator import attrgetter
import logging
import threading

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib.packet import packet, ethernet, ipv4

import adaptiveswitch
import utils


logging.basicConfig(level=logging.DEBUG,
                    format="[%(levelname)s %(asctime)s] %(name)s.%(funcName)s %(message)s",
                    datefmt='%Y%m%d %H:%M:%S')


class AdaptiveMonitor(adaptiveswitch.AdaptiveSwitch):
    def __init__(self, *args, **kwargs):
        logging.info("method AdaptiveMonitor.__init__")
        super(AdaptiveMonitor, self).__init__(*args, **kwargs)
        self.datapath_list_monitor = {}
        self.port_list = {}
        self.mac_list = {}
        self.ip_list = {}

        #the rest is for monitoring flows
        self.in_ip_list = {}
        self.out_ip_list = {}
        self.in_out_ip_list = {}

        self.monitor_thread = hub.spawn(self._monitor)

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        logging.info("method AdaptiveMonitor._state_change_handler")
        super(AdaptiveMonitor, self)._state_change_handler(ev)
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list_monitor:
                self.datapath_list_monitor[datapath.id] = datapath
                self.port_list[datapath.id] = []
                self.mac_list[datapath.id] = []
                self.ip_list[datapath.id] = []
                self.in_ip_list[datapath.id] = []
                self.out_ip_list[datapath.id] = []
                self.in_out_ip_list[datapath.id] = []

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list_monitor:
                del self.datapath_list_monitor[datapath.id]
                del self.port_list[datapath.id]
                del self.mac_list[datapath.id]
                del self.ip_list[datapath.id]
                del self.in_in_list[datapath.id]
                del self.out_ip_list[datapath.id]
                self.in_out_ip_list[datapath.id]

    #monitor thread
    def _monitor(self):
        logging.info("method AdaptiveMonitor._monitor")
        while True:
            print "in _monitor function"
            for dp in self.datapath_list.values():
                print dp
                print dp.id
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            #add operations to insert and delete monitoring flows entries according the statistics information
            hub.sleep(20)

    #packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        logging.info("method AdaptiveMonitor._packet_in_handler")
        super(AdaptiveMonitor, self)._packet_in_handler(ev)
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.match['in_port']
        print "111\n"
        print self.port_list.keys()
        print "222\n"
        print in_port
        print "333\n"
        self.port_list[datapath.id].append(in_port)

        pkt = packet.Packet(msg.data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
#            print type(pkt_ipv4)
#            print pkt_ipv4
#            print pkt_ipv4.src
#            print pkt_ipv4.dst
            src = pkt_ipv4.src
            dst = pkt_ipv4.dst
            self.ip_list[datapath.id].append(src)
            self.ip_list[datapath.id].append(dst)
#            self.in_ip_list[datapath.id].append(src)
#            self.out_ip_list[datapath.id].append(dst)
#            self.in_out_ip_list[datapath.id].append((src, dst))
            self.add_monitor(datapath, in_ip=src, out_ip=None)
            self.add_monitor(datapath, in_ip=None, out_ip=dst)
            self.add_monitor(datapath, in_ip=src, out_ip=dst)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth:
            src = eth.src
            dst = eth.dst
            self.mac_list[datapath.id].append(src)
            self.mac_list[datapath.id].append(dst)

            #register in ip flow entry
            #register out ip flow entry
            #register in ip flow entry

    #flow status receiver
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        logging.info("method AdaptiveMonitor._flow_stats_reply_handler")
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                         (stat.table_id, stat.duration_sec, stat.duration_nsec, stat.priority, stat.idle_timeout,
                          stat.hard_timeout, stat.flags, stat.cookie, stat.packet_count, stat.byte_count, stat.match,
                          stat.instructions))
        print flows
        print "\n\n"
        logging.debug('FlowStats: %s', flows)
        body = ev.msg.body
        logging.debug('datapath         in-port  eth-dst           out-port packets  bytes   ')
        logging.debug('---------------- -------- ----------------- -------- -------- --------')
        for flow in body:
            print "bbbbssss"
            print flow
            print flow.match
            print type(flow.match)
            print "in_port" in flow.match
            print "eth_dst" in flow.match
            try:
                print "syccessful"
                print flow.match["in_port"]
                print flow.match["eth_dst"]
            except Exception as ex:
                print flow.match

        filter_flow_table = [flow for flow in body if "in_port" in flow.match and "eth_dst" in flow.match]
        print "filter_flow_table =", filter_flow_table
        for stat in sorted(filter_flow_table, key=lambda f: (f.match['in_port'], f.match['eth_dst'])):
            logging.debug('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'],
                         stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)

    #port status receiver
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        logging.info("method AdaptiveMonitor._port_stats_reply_handler")
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                         'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d '
                         'rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d '
                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                         'collisions=%d duration_sec=%d duration_nsec=%d' %
                         (stat.port_no, stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes, stat.rx_dropped,
                          stat.tx_dropped, stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err,
                          stat.rx_crc_err, stat.collisions, stat.duration_sec, stat.duration_nsec))
        print ports
        print "\n\n"
        logging.debug('PortStats: %s', ports)
        body = ev.msg.body
        #        filter_flow_table = filter([flow for flow in body], flow.hasattr('inport') and flow.hasattr("eth_dst"))
        logging.debug('datapath         port     rx-pkts  rx-bytes rx-error tx-pkts  tx-bytes tx-error')
        logging.debug('---------------- -------- -------- -------- -------- -------- -------- --------')
        #        for stat in sorted(body, key=attrgetter('port_no')):
        for stat in sorted(body, key=lambda l: l.port_no):
            logging.info('%016x %8x %8d %8d %8d %8d %8d %8d', ev.msg.datapath.id, stat.port_no, stat.rx_packets,
                        stat.rx_bytes, stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    @staticmethod
    def _request_flow_stats(datapath):
        logging.info("method AdaptiveMonitor._request_flow_stats datapath = %16x" % datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @staticmethod
    def _request_port_stats(datapath):
        logging.info("method AdaptiveMonitor._request_port_stats datapath = %16x" % datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def add_monitor(self, datapath, in_ip=None, out_ip=None):
        parser = datapath.ofproto_parser
        if in_ip is None and out_ip is not None:
            self.in_ip_list[datapath.id].append(in_ip)
            match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip)
            inst = [parser.OFPInstructionGotoTable(1)]
            self.add_flow(datapath, 0, 3, match_ip, inst)
            return
        if in_ip is not None and out_ip is None:
            self.out_ip_list[datapath.id].append(out_ip)
            match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=out_ip)
            inst = [parser.OFPInstructionGotoTable(2)]
            print datapath.id
            print utils.to_string(match_ip)
            print utils.to_string(inst)
            self.add_flow(datapath, 1, 3, match_ip, inst)
            return
        if in_ip is not None and out_ip is not None:
            self.in_out_ip_list[datapath.id].append((in_ip, out_ip))
            match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip, ipv4_dst=out_ip)
            inst = [parser.OFPInstructionGotoTable(3)]
            self.add_flow(datapath, 2, 3, match_ip, inst)
            return

    def del_monitor(self, datapath, in_ip=None, out_ip=None):
        parser = datapath.ofproto_parser
        if in_ip is None and out_ip is not None:
            try:
                self.in_ip_list[datapath.id].remove(in_ip)
                match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip)
                self.del_flow(datapath, match_ip)
            except ValueError as ex:
                logging.exception("del_flow for in_ip = %s on %16xd failed" % (in_ip, datapath.id))
            return
        if in_ip is not None and out_ip is None:
            try:
                self.out_ip_list[datapath.id].remove(out_ip)
                match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=out_ip)
                self.del_flow(datapath, match_ip)
            except ValueError as ex:
                logging.exception("del_flow for out_ip = %s on %16xd failed" % (in_ip, datapath.id))
            return
        if in_ip is not None and out_ip is not None:
            try:
                self.flow_list[datapath.id].remove((in_ip, out_ip))
                match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip, ipv4_dst=out_ip)
                self.del_flow(datapath, match_ip)
            except ValueError as ex:
                logging.exception("del_flow for (ip_in = %s, out_ip = %s) on %16xd failed" % (in_ip, out_ip, datapath.id))
            return