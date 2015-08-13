from webob.static import DirectoryApp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager

from multiprocessing import Process

import os
from threading import *
from pprint import pprint
from zlib import crc32 # used to create unique cookies for flows
import pyjsonrpc
from collections import namedtuple

PATH = os.path.dirname(__file__)


class SimpleSwitch13(app_manager.RyuApp):
    '''An extention of the simple example switch. This module includes remote installaiton and monitoring of meters'''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
	'''Sends messages to switch to get information about them'''
        datapath = ev.msg.datapath
        self.ofproto = datapath.ofproto
        self.parser = datapath.ofproto_parser
	parser = self.parser
	#delete existing flows - stops conflicts
	self.del_all_flows(datapath)
	self.send_barrier_request(datapath)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = self.parser.OFPMatch()
        actions = [self.parser.OFPActionOutput(self.ofproto.OFPP_CONTROLLER,
                                          self.ofproto.OFPCML_NO_BUFFER)]

	
	#flow mod for table miss :packetin to contoller if unrecognised by switch
	self.add_flow(datapath, 1, match, actions)
	
	#no lldp
	self.add_flow(datapath, 1, parser.OFPMatch(eth_type=0x88cc), [])

	
	#Add meter for ports
	self.add_meter_port(datapath,26,20000)
        self.add_meter_port(datapath,28,20000)
        self.add_meter_port(datapath,30,20000)
        self.add_meter_port(datapath,32,20000)
        self.add_meter_port(datapath,34,20000)
        self.add_meter_port(datapath,35,50000) #Meter in other direction
	#Add flows for bridge and include relevant meter
	#if in on 26 out on ....

	#Match for 26. Out on 25 meter 26
	match = parser.OFPMatch(in_port=26)
	actions = [parser.OFPActionOutput(25)]	
	self.add_flow(datapath, 100, match, actions, meters=[26])
	#Match for 28. Out on 27 meter 28
        match = parser.OFPMatch(in_port=28)                     
        actions = [parser.OFPActionOutput(27)]                 
        self.add_flow(datapath, 100, match, actions, meters=[28])
   
	#Match for 30. Out on 29 meter 30
        match = parser.OFPMatch(in_port=30)
        actions = [parser.OFPActionOutput(29)]
        self.add_flow(datapath, 100, match, actions, meters=[30])

	#Match for 32. Out on 31 meter 32
        match = parser.OFPMatch(in_port=32)
        actions = [parser.OFPActionOutput(31)]
        self.add_flow(datapath, 100, match, actions, meters=[32])

	#Match for 34. Out on 33 meter 34
        match = parser.OFPMatch(in_port=34)
        actions = [parser.OFPActionOutput(33)]
        self.add_flow(datapath, 100, match, actions, meters=[34])

	#Match for 36. Out on 35 meter 36
        match = parser.OFPMatch(in_port=36)
        actions = [parser.OFPActionOutput(35)]
        self.add_flow(datapath, 100, match, actions, meters=[])



	#Flows for the opposite direction, no meters

	#Match for 25. Out on 26
        match = parser.OFPMatch(in_port=25)
        actions = [parser.OFPActionOutput(26)]
        self.add_flow(datapath, 100, match, actions, meters=[])
        #Match for 27. Out on 28
        match = parser.OFPMatch(in_port=27)
        actions = [parser.OFPActionOutput(28)]
        self.add_flow(datapath, 100, match, actions, meters=[])

        #Match for 29. Out on 30 meter 30
        match = parser.OFPMatch(in_port=29)
        actions = [parser.OFPActionOutput(30)]
        self.add_flow(datapath, 100, match, actions, meters=[])

        #Match for 31. Out on 32 meter 32
        match = parser.OFPMatch(in_port=31)
        actions = [parser.OFPActionOutput(32)]
        self.add_flow(datapath, 100, match, actions, meters=[])

        #Match for 33. Out on 34 meter 34
        match = parser.OFPMatch(in_port=33)
        actions = [parser.OFPActionOutput(34)]
        self.add_flow(datapath, 100, match, actions, meters=[])

        #Match for 35. Out on 36 meter 36. This port is different, we want to meter incoming traffic in the other direction
        match = parser.OFPMatch(in_port=35)
        actions = [parser.OFPActionOutput(36)]
        self.add_flow(datapath, 100, match, actions, meters=[35])






    def add_flow(self, datapath, priority, match, actions, buffer_id=None, meters=[], timeout=0, cookie=0, table_num=100):
        '''Add a flow to a datapath - modified to allow meters'''
	ofproto = datapath.ofproto
        parser = datapath.ofproto_parser       
 	#print ("Add flow, %s" % hex(cookie))
	
	#If destination is FF do not install flow. (Caused by switches flooding each other)
	
	inst = []
	self.logger.info("Installing flow on %s",self._dp_name(datapath.id))
        # print "The meter is :",meter

	if actions != []:
            inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions))



	for meter in meters:
            # print "Sending flow mod with meter instruction, meter :", meter
	    if meter == -1:
	        inst.append(parser.OFPInstructionGotoTable(200))
	    #elif meter<50:
	    inst.append(parser.OFPInstructionMeter(meter))
	#	table_num=200
         #   else:
	#	if actions != []:
	#	     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),parser.OFPInstructionMeter(meter),parser.OFPInstructionGotoTable(200)]
	#	else:
	#	     inst = [parser.OFPInstructionMeter(meter),parser.OFPInstructionGotoTable(200)]


        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=timeout,
                                    idle_timeout=timeout, table_id=table_num, cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    hard_timeout=timeout, idle_timeout=timeout, table_id=table_num, cookie=cookie)
        datapath.send_msg(mod)

    def send_barrier_request(self, datapath):
        datapath.send_msg(datapath.ofproto_parser.OFPBarrierRequest(datapath))

    def add_meter_port(self, datapath, port_no, speed):
    	'''Adds a meter to a port on a switch. speed argument is in kbps'''
        print "ADDING METER TO PORT " + str(port_no) + " at " + str(speed) + " on dpid "+ str(datapath.id)
	
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

	#METER ID's WILL DIRECTLY RELATE TO PORT NUMBERS
        #change meter with meter_id <port_no>, on switch <datapath>, to have a rate of <speed>

        bands=[]
        
	#set starting bit rate of meter
        dropband = parser.OFPMeterBandDrop(rate=int(speed), burst_size=0)
	bands.append(dropband)
        #Delete meter incase it already exists (other instructions pre installed will still work)
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_DELETE,flags=ofproto.OFPMF_KBPS,meter_id=int(port_no),bands=bands)
        datapath.send_msg(request)
        #Create meter
        request = parser.OFPMeterMod(datapath=datapath,command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_KBPS,meter_id=int(port_no),bands=bands)
        datapath.send_msg(request)
        return 1

    def del_all_flows(self, datapath):
	'''Deletes all flows. Useful for when the controller is restarted
	   and we want to get rid of flows from a previous experiment'''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # msg = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=parser.OFPMatch(), table_id=ofproto.OFPTT_ALL)
        # datapath.send_msg(msg)
        #datapath.send_msg(parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=parser.OFPMatch(), table_id=100))
	self.logger.info("Delete all flows on dp %s", datapath.id)

        match = parser.OFPMatch()
        instructions = []

        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, 100, ofproto.OFPFC_DELETE, 0, 0, 1, ofproto.OFPCML_NO_BUFFER, ofproto.OFPP_ANY, ofproto.OFPG_ANY, 0, match, instructions)
	datapath.send_msg(flow_mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''Event triggered when packet is sent to the controller from the switch (packetin).
	   Mods are install for the switch to remember the packet and for meters for the flow.'''

	# If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        
	dpid = datapath.id
	# print('DPID', dpid)
	#self.logger.info("%s", self.datapathdict)
        self.logger.info("packet in %s %s %s %s", self._dp_name(dpid), src, dst, in_port)


    #handle port stats replies
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
	'''Event: reply of throughput on a datapath. Saved for later so it can be requested and analysed'''
	#TODO change bytes to Kbits. Before change make sure everything that uses it is ready to use kbits not bytes	
        def _unpack(portStats):
            unpacked = {}
            for statsEntry in portStats:
                port = statsEntry.port_no
                if port != 4294967294: # this magic number is the 'local'port, which is not real.... 
		    #WARNING. Change here from bytes to kbits. TODO change names to say tx_kbits
                    unpacked[port] = TimedPortStatRecord (statsEntry.tx_packets, statsEntry.rx_packets, (statsEntry.tx_bytes*8)/1000, (statsEntry.rx_bytes*8)/1000, statsEntry.duration_sec, statsEntry.duration_nsec )
            return unpacked

	maxStats_debug={}
	rate_debug={}

        # on first entry for a switch just save the stats, initiliase the max counters to zero and exit
        if ev.msg.datapath.id not in self.PORT_CURRENT:
            self.PORT_CURRENT[ev.msg.datapath.id] = _unpack(ev.msg.body)
            self.PORT_MAX[ev.msg.datapath.id] = {}
            self.PORT_RATE[ev.msg.datapath.id] = {}
            maxStats = self.PORT_MAX[ev.msg.datapath.id]
            for statsEntry in ev.msg.body:
                if statsEntry.port_no != 4294967294: # this magic number is the 'local'port, which is not real....
                    maxStats[statsEntry.port_no] = PortStatRecord(0,0,0,0)

        else: # we have a previous stats record so it is now possible to calculate the delta
            oldStats = self.PORT_CURRENT[ev.msg.datapath.id]
            newStats = _unpack(ev.msg.body)
            self.PORT_CURRENT[ev.msg.datapath.id] = newStats # save away this dataset for the next time around...
            maxStats = self.PORT_MAX[ev.msg.datapath.id]     # always exists since it is initialised to zero on first stats report
            rate     = self.PORT_RATE[ev.msg.datapath.id]
	
            for port in newStats:
            # now check if there are any new ports in this report - in which case we cannot do anything other than initilaise the max values to zero
                if port not in oldStats:
                    maxStats[port] = PortStatRecord(0,0,0,0)
                    rate[port]     = PortStatRecord(0,0,0,0)

		    maxStats_debug[port] = [0,0]
                    rate_debug[port]     = [0,0]
                else:
                    delta_time = self.diff_time(oldStats[port].duration_sec, oldStats[port].duration_nsec, newStats[port].duration_sec, newStats[port].duration_nsec)
                    # print "delta time: %f\n" % delta_time
                    if (delta_time<0):
                        print "diff_time failure(port stats)?"
                        pprint(ev.msg.body)
                    else:
   			#TODO change bytes to kbits 
                        rate[port] = PortStatRecord ((newStats[port].tx_packets - oldStats[port].tx_packets) / delta_time,
                                                        (newStats[port].rx_packets - oldStats[port].rx_packets) / delta_time,
                                                        (newStats[port].tx_bytes - oldStats[port].tx_bytes) / delta_time,
                                                        (newStats[port].rx_bytes - oldStats[port].rx_bytes) / delta_time)


                        maxStats[port] = PortStatRecord ( max(maxStats[port].tx_packets,rate[port].tx_packets),
                                                      max(maxStats[port].rx_packets,rate[port].rx_packets),
                                                      max(maxStats[port].tx_bytes,rate[port].tx_bytes),
                                                      max(maxStats[port].rx_bytes,rate[port].rx_bytes) )

						
			rate_debug[port] = [format((((newStats[port].tx_bytes - oldStats[port].tx_bytes) / delta_time)),'.2f'),
                                                       format((((newStats[port].rx_bytes - oldStats[port].rx_bytes) / delta_time)),'.2f')]

                        maxStats_debug[port] = [format((max(maxStats[port].tx_bytes,rate[port].tx_bytes)),'.2f'),
								format((max(maxStats[port].rx_bytes,rate[port].rx_bytes)),'.2f')]


	    # visualise the stats in the server side
            print self._dp_name(ev.msg.datapath.id)
	    print "Port - current"
            pprint(rate_debug)
            print "Port - maximum"
            pprint(maxStats_debug)





    def _dp_name(self, dpid):
        '''Converts dpids to openflow instance names. Just for debugging'''
        name=dpid
        if '239' in str(dpid):
            name = 't'
        elif '2115686243633600' in str(dpid):
            name = 'b'
        elif '708311360080320' in str(dpid):
            name = 'p1'
        elif '989786336790976' in str(dpid):
            name = 'p2'
        elif '1271261313501632' in str(dpid):
            name = 'p3'
        elif '1552736290212288' in str(dpid):
            name = 'p4'
        elif '1834211266922944' in str(dpid):
            name = 'p5'

        return name
