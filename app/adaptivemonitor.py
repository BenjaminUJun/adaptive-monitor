#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import logging
import time

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether
from ryu.lib.packet import packet, ethernet, ipv4

import adaptiveswitch


class AdaptiveMonitor(adaptiveswitch.AdaptiveSwitch):
    def __init__(self, *args, **kwargs):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor INIT & LOGGING START" % time.strftime("%Y-%m-%d %H:%M:%S"))

        super(AdaptiveMonitor, self).__init__(*args, **kwargs)
        self.datapath_list_monitor = {}
        self.port_list = {}
        self.mac_list = {}
        self.ip_list = {}

        #the rest is for monitoring flows
        self.in_ip_list = {}
        self.out_ip_list = {}
        self.in_out_ip_list = {}
        self.ip_to_mac = {}

        self.monitor_thread = hub.spawn(self._monitor)

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor._state_change_handler Datapath $d" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), ev.datapath.id))
        super(AdaptiveMonitor, self)._state_change_handler(ev)
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list_monitor:
                logging.log(logging.INFO,
                            "[INFO %s] AdaptiveMonitor._state_change_handler Register Datapath %16d" % (
                                time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
                self.datapath_list_monitor[datapath.id] = datapath
                self.port_list[datapath.id] = []
                self.mac_list[datapath.id] = []
                self.ip_list[datapath.id] = []
                self.in_ip_list[datapath.id] = []
                self.out_ip_list[datapath.id] = []
                self.in_out_ip_list[datapath.id] = []
                self.ip_to_mac[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list_monitor:
                logging.log(logging.INFO,
                            "[INFO %s] AdaptiveMonitor._state_change_handler Unregister Datapath %16d" % (
                                time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
                del self.datapath_list_monitor[datapath.id]
                del self.port_list[datapath.id]
                del self.mac_list[datapath.id]
                del self.ip_list[datapath.id]
                del self.in_ip_list[datapath.id]
                del self.out_ip_list[datapath.id]
                del self.in_out_ip_list[datapath.id]
                del self.ip_to_mac[datapath.id]

    #monitor thread
    def _monitor(self):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor._monitor" % time.strftime("%Y-%m-%d %H:%M:%S"))
        while True:
            for dp in self.datapath_list.values():
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
                #if received count then calc elephant flow and adjust monitor entries
            #add operations to insert and delete monitoring flows entries according the statistics information
            hub.sleep(20)

    #packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor._packet_in_handler" % time.strftime("%Y-%m-%d %H:%M:%S"))
        super(AdaptiveMonitor, self)._packet_in_handler(ev)
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.match['in_port']
        self.port_list[datapath.id].append(in_port)

        pkt = packet.Packet(msg.data)

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not pkt_ipv4:
            return
        src_ip = pkt_ipv4.src
        dst_ip = pkt_ipv4.dst
        self.ip_list[datapath.id].append(src_ip)
        self.ip_list[datapath.id].append(dst_ip)
        self.in_ip_list[datapath.id].append(src_ip)
        self.out_ip_list[datapath.id].append(dst_ip)
        self.in_out_ip_list[datapath.id].append((src_ip, dst_ip))

        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if not pkt_eth:
            return
        src_mac = pkt_eth.src
        dst_mac = pkt_eth.dst
        self.mac_list[datapath.id].append(src_mac)
        self.mac_list[datapath.id].append(dst_mac)

        self.ip_to_mac[src_ip] = src_mac
        self.ip_to_mac[dst_ip] = dst_mac

        self.add_monitor(datapath, in_ip=src_ip, out_ip=dst_ip)

    #flow status receiver
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        logging.log(logging.INFO,
                    "[INFO %s] AdaptiveMonitor._flow_stats_reply_handler" % time.strftime("%Y-%m-%d %H:%M:%S"))
        flows = []
        flows.extend(ev.msg.body)
        #        for stat in ev.msg.body:
        #            flows.append('table_id=%s '
        #                         'duration_sec=%d duration_nsec=%d '
        #                         'priority=%d '
        #                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
        #                         'cookie=%d packet_count=%d byte_count=%d '
        #                         'match=%s instructions=%s' %
        #                         (stat.table_id, stat.duration_sec, stat.duration_nsec, stat.priority, stat.idle_timeout,
        #                          stat.hard_timeout, stat.flags, stat.cookie, stat.packet_count, stat.byte_count, stat.match,
        #                          stat.instructions))
        #        self.logger.debug('FlowStats: %s', flows)
        logging.log(logging.DEBUG, 'datapath         in-port  eth-dst           out-port packets  bytes   ')
        logging.log(logging.DEBUG, '---------------- -------- ----------------- -------- -------- --------')
        filter_flow_table = [flow for flow in flows if "in_port" in flow.match and "eth_dst" in flow.match]
        sorted_flow_table = sorted(filter_flow_table, key=lambda f: f.byte_count)
        for stat in sorted_flow_table:
            logging.log(logging.DEBUG, "[INFO %s]%016x %8x %17s %8x %8d %8d", (
                time.strftime("%Y-%m-%d %H:%M:%S"), ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'],
                stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count))

    #port status receiver
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        logging.log(logging.INFO,
                    "[INFO %s] AdaptiveMonitor._port_stats_reply_handler" % time.strftime("%Y-%m-%d %H:%M:%S"))
        ports = []
        ports.extend(ev.msg.body)
        #        for stat in ev.msg.body:
        #            ports.append('port_no=%d '
        #                         'rx_packets=%d tx_packets=%d '
        #                         'rx_bytes=%d tx_bytes=%d '
        #                         'rx_dropped=%d tx_dropped=%d '
        #                         'rx_errors=%d tx_errors=%d '
        #                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
        #                         'collisions=%d duration_sec=%d duration_nsec=%d' %
        #                         (stat.port_no, stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes, stat.rx_dropped,
        #                          stat.tx_dropped, stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err,
        #                          stat.rx_crc_err, stat.collisions, stat.duration_sec, stat.duration_nsec))
        logging.log(logging.DEBUG,
                    '[DEBUG %s] datapath         port     rx-pkts  rx-bytes rx-error tx-pkts  tx-bytes tx-error' % time.strftime(
                        "%Y-%m-%d %H:%M:%S"))
        logging.log(logging.DEBUG,
                    '[DEBUG %s]---------------- -------- -------- -------- -------- -------- -------- --------' % time.strftime(
                        "%Y-%m-%d %H:%M:%S"))
        filter_port_table = filter([port for port in ports], port.hasattr('inport') and port.hasattr("eth_dst"))
        sorted_port_table = sorted(filter_port_table, key=lambda l: l.port_no)
        for stat in sorted_port_table:
            logging.log(logging.DEBUG, '%016x %8x %8d %8d %8d %8d %8d %8d' % (
                time.strftime("%Y-%m-%d %H:%M:%S"), ev.msg.datapath.id, stat.port_no, stat.rx_packets, stat.rx_bytes,
                stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors))

    def _request_flow_stats(self, datapath):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor._request_flow_stats datapath = %16x" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @staticmethod
    def _request_port_stats(datapath):
        logging.log(logging.INFO, "[INFO %s] AdaptiveMonitor._request_port_stats datapath = %16x" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def add_monitor(self, datapath, in_ip, out_ip):
        if self.ip_to_mac[datapath.id][out_ip] in self.mac_to_port:
            out_port = self.mac_to_port[self.ip_to_mac[datapath.id][out_ip]]

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip, ipv4_dst=out_ip)

        actions = [parser.OFPActionOutput(super(AdaptiveMonitor).MIRROR_PORT), parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, 3, match_ip, inst)


    def del_monitor(self, datapath, in_ip, out_ip):
        parser = datapath.ofproto_parser
        try:
            self.flow_list[datapath.id].remove((in_ip, out_ip))
            match_ip = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=in_ip, ipv4_dst=out_ip)
            self.del_flow(datapath, match_ip)
        except ValueError as ex:
            self.logger.exception(
                "del_flow for (ip_in = %s, out_ip = %s) on %16xd failed" % (in_ip, out_ip, datapath.id))
        return