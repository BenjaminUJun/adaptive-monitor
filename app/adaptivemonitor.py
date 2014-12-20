#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-


from operator import attrgetter
import logging

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4

import adaptiveswitch
import utils


logger = logging.getLogger()


class AdaptiveMonitor(adaptiveswitch.AdaptiveSwitch):

    def __init__(self, *args, **kwargs):
        logger.info("method AdaptiveMonitor.__init__")
        super(AdaptiveMonitor, self).__init__(*args, **kwargs)
        self.port_list = {}
        self.mac_list = {}
        self.ip_list = {}
        self.flow_count = {}
        self.monitor_thread = hub.spawn(self._monitor)

    #switch register
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        logger.info("method AdaptiveMonitor._state_change_handler")
        super(AdaptiveMonitor, self)._state_change_handler(self, ev)
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapath_list:
                self.port_list[datapath.id] = []
                self.mac_list[datapath.id] = []
                self.ip_list[datapath.id] = []
                self.flow_count[datapath.id] = []

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapath_list:
                del self.port_list[datapath.id]
                del self.mac_list[datapath.id]
                del self.ip_list[datapath.id]
                del self.flow_count[datapath.id]

    #monitor thread
    def _monitor(self):
        logger.info("method AdaptiveMonitor._monitor")
        while True:
            print "in _monitor function"
            for dp in self.datapath_list.values():
                self._request_flow_stats(dp)
                self._request_port_stats(dp)
            hub.sleep(10)

    #packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        super(AdaptiveMonitor, self)._packet_in_handler
        msg = ev.msg
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            print type(pkt_ipv4)
            print pkt_ipv4
            print pkt_ipv4.src
            print pkt_ipv4.dst
            self.ip_list[datapath.id].append(pkt_ipv4.src)
            self.ip_list[datapath.id].append(pkt_ipv4.dst)
            self.flow_count[datapath.id].append((pkt_ipv4.src, pkt_ipv4.dst))

            #register in ip flow entry
            #register out ip flow entry
            #register in ip flow entry

    #flow status receiver
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                        (stat.table_id, stat.duration_sec, stat.duration_nsec, stat.priority, stat.idle_timeout, stat.hard_timeout, stat.flags, stat.cookie, stat.packet_count, stat.byte_count, stat.match, stat.instructions))
        print flows
        print "\n\n"
        logger.debug('FlowStats: %s', flows)
        body = ev.msg.body
        logger.debug('datapath         in-port  eth-dst           out-port packets  bytes   ')
        logger.debug('---------------- -------- ----------------- -------- -------- --------')
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
            logger.debug('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)

    #port status receiver
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                         'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d '
                         'rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d '
                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                         'collisions=%d duration_sec=%d duration_nsec=%d' %
                         (stat.port_no, stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes, stat.rx_dropped, stat.tx_dropped, stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err, stat.rx_crc_err, stat.collisions, stat.duration_sec, stat.duration_nsec))
        print ports
        print "\n\n"
        logger.debug('PortStats: %s', ports)
        body = ev.msg.body
#        filter_flow_table = filter([flow for flow in body], flow.hasattr('inport') and flow.hasattr("eth_dst"))
        logger.debug('datapath         port     rx-pkts  rx-bytes rx-error tx-pkts  tx-bytes tx-error')
        logger.debug('---------------- -------- -------- -------- -------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            logger.info('%016x %8x %8d %8d %8d %8d %8d %8d', ev.msg.datapath.id, stat.port_no, stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors)

    def _request_flow_stats(self, datapath):

        logger.info('send flow stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):
        logger.info('send flow stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)