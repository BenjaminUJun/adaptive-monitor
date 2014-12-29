#!/usr/bin/env python2.7
# -*- coding:utf-8 -*-

import json
import logging
import time

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib

import adaptivemonitor


simple_switch_name = 'simple_switch'
url1 = '/simpleswitch/mactable/{dpid}'
url2 = '/simpleswitch/statinfo/{dpid}'
SWITCH_ID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'


class SimpleSwitchRest(adaptivemonitor.AdaptiveMonitor):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):

        logging.log(logging.INFO,
                    "[INFO %s] SimpleSwitchRest__init__" % time.strftime("%Y-%m-%d %H:%M:%S"))
        super(SimpleSwitchRest, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController, {simple_switch_name: self})

    def set_mac_to_port(self, datapath_id, entry):
        logging.log(logging.INFO, "[INFO %s] SimpleSwitchRest.set_mac_to_port" % time.strftime("%Y-%m-%d %H:%M:%S"))
        mac_to_port_f = self.mac_to_port.setdefault(datapath_id, {})
        datapath = self.datapath_list[datapath_id]
        if datapath is None:
            return
        ofproto = datapath.ofproto

        entry_mac = entry['mac']
        entry_port = entry['port']

        parser = datapath.ofproto_parser
        if not entry_port in mac_to_port_f.values():
            for mac, port in mac_to_port_f.items():
                actions = [parser.OFPActionOutput(entry_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                self.add_flow(datapath, 2, match, inst)

                actions = [parser.OFPActionOutput(port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                self.add_flow(datapath, 2, match, inst)
            mac_to_port_f.update({entry_mac: entry_port})
        return mac_to_port_f


class SimpleSwitchController(ControllerBase):
    def __init__(self, req, link, data, **config):
        logging.log(logging.INFO, "[INFO %s] SimpleSwitchController.__init__" % time.strftime("%Y-%m-%d %H:%M:%S"))
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_spp = data[simple_switch_name]


    @route('simpleswitch', url1, methods=['GET'], requirements={'datapathid': SWITCH_ID_PATTERN})
    def _list_mac_table(self, req, **kwargs):
        logging.log(logging.INFO,
                    "[INFO %s] SimpleSwitchController._list_mac_table" % time.strftime("%Y-%m-%d %H:%M:%S"))
        simple_switch = self.simple_switch_spp
        datapath_id = dpid_lib.str_to_dpid(kwargs['dpid'])
        if datapath_id not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(datapath_id, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url1, methods=['PUT'], requirements={'dpid': SWITCH_ID_PATTERN})
    def _put_mac_table(self, req, **kwargs):
        logging.log(logging.INFO,
                    "[INFO %s] SimpleSwitchController._put_mac_table" % time.strftime("%Y-%m-%d %H:%M:%S"))
        simple_switch = self.simple_switch_spp
        datapath_id = dpid_lib.str_to_dpid(kwargs['dpid'])
        new_entry = eval(req.body)

        if not datapath_id in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.set_mac_to_port(datapath_id, new_entry)
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    @route('simpleswitch', url2, methods=['PUT'], requirements={'dpid': SWITCH_ID_PATTERN})
    def _put_stat_info(self, req, **kwargs):
        logging.log(logging.INFO,
                    "[INFO %s] SimpleSwitchController._put_stat_info" % time.strftime("%Y-%m-%d %H:%M:%S"))
        new_entry = eval(req.body)
        logging.log(logging.INFO, "[INFO %s] SimpleSwitchController._put_stat_info %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), str(new_entry)))

        datapath_id = dpid_lib.str_to_dpid(kwargs['dpid'])
        flow_count = eval(kwargs['count'])
