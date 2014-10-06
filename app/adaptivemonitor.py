from operator import attrgetter

import adaptiveswitch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

class AdaptiveMonitor(adaptiveswitch.AdaptiveSwitch):

    def __init__(self, *args, **kwargs):
        super(AdaptiveMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)


    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

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
###        print flows
###        print "\n\n"
####        self.logger.debug('FlowStats: %s', flows)
###        body = ev.msg.body
###        self.logger.info('datapath         in-port  eth-dst           out-port packets  bytes   ')
###        self.logger.info('---------------- -------- ----------------- -------- -------- --------')
###        for stat in sorted([flow for flow in body], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
###            self.logger.info('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)

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
###        print ports
###        print "\n\n"
####        self.logger.debug('PortStats: %s', ports)
###        body = ev.msg.body
###        self.logger.info('datapath         port     rx-pkts  rx-bytes rx-error tx-pkts  tx-bytes tx-error')
###        self.logger.info('---------------- -------- -------- -------- -------- -------- -------- --------')
###        for stat in sorted(body, key=attrgetter('port_no')):
###            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d', v.msg.datapath.id, stat.port_no, stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors)
