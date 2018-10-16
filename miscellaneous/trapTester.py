#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 7th, 2018
#File: trapTester.py

from lib.nm_header import *
import lib.Nm as Nm

import subprocess
import time
#import os
#import sys
#import select
#from pygtail import Pygtail    #download and install pygtail package under /Library/Python/2.7/site-packages
#from lib.nm_header import *
#import lib.Nm as Nm
#Download pygtail at: https://github.com/bgreenlee/pygtail

'''
Pygtail's options:
    offset_file=options.offset_file,
    paranoid=options.paranoid,
    every_n=options.every_n,
    copytruncate=not options.no_copytruncate,
    ead_from_end=options.read_from_end)
'''
# pwd = os.getcwd()
# print "Current Working Direcgtory %s\n" % (pwd)
#
# NET_MGR_PATH = ''
# from sys import platform
# if platform == "darwin" or platform == "linux":
#     NET_MGR_PATH = pwd + '/nm'                 #'/mac_tools/net_mgr'
# elif platform == "linux2":                  #Raspberry Pi
#     NET_MGR_PATH = pwd + '/Nm'   #''/arm_tools/net_mgr'
#

""" 
Currently, to run this script, it is assumed you have setup a local net_trap server, IPV6, and port associated with it
as well as the path to log output. ie. /tmp/trap_file.txt

Call this program from project root directory: python -m miscellaneous.trapTester.py
"""
#List of traps that are currently testable via a net_mgr's nmtrap force command(only 18 out of 71 are testable this way.


#Quick Dictionary use for Debugging
#trapsToTest = {
#'power_loss':'0xcf',
#'power_restore':'0xd0',
#'battery_off': '0x11f',
#'battery_on':'0x11e',
#'battery_config_mismatched':'0x379',
#}

"""
trapsToTest = {
'power_loss':'0xcf',
'power_restore':'0xd0',
'battery_off': '0x11f',
'battery_on':'0x11e',
'battery_config_mismatched':'0x379',
'imu_alarm': '0x130',
'lg_bundled_power_loss':'0x1ca',
'private_key_failure':'0x1bc',
'no_battery_rt':'0x1d8',
'tamper_trap':'0x299',
'pb_tamper_trap 0':'0x4c5',
'pb_tamper_trap 1':'0x4c5',
'changed_id':'0x2f5',
'open_gates':'0x301',
'lcs_event_status':'0x356',
'no_location':'0x456',
'location_update':'0x41b',
'high_temp':'0x468',
'authority_key_missing':'0x529',
}
"""
trapsToTest = {
'power_loss':'0xcf',
'power_restore':'0xd0',
'battery_off': '0x11f',
'battery_on':'0x11e',
'battery_config_mismatched':'0x379',
'imu_alarm': '0x130',
'lg_bundled_power_loss':'0x1ca',
'private_key_failure':'0x1bc',
'no_battery_rt':'0x1d8',
'tamper_trap':'0x299',
'pb_tamper_trap 0':'0x4c5',
'pb_tamper_trap 1':'0x4c5',
'changed_id':'0x2f5',
'open_gates':'0x301',
'lcs_event_status':'0x356',
'no_location':'0x456',
'location_update':'0x41b',
'high_temp':'0x468',
'authority_key_missing':'0x529',
'sntp_poll_fail':'0x00',
'i5s_reg':'0x00',
'coap_sec':'0x00',
'coap_sec_pub':'0x00',
'trap_conf_reqd':'0x00',
'bpd_nreg':'0x00',
'dhcp_lease_alarm':'0x00',
'ap_call_home_req':'0x00',
'esp_trap':'0x00',
'esp_unsolicited':'0x00',
'lg_reg_fail':'0x00',
'private_key_failure':'0x00',
'no_battery_rt':'0x00',
'tamper_trap':'0x00',
'changed_id':'0x00',
'open_gates':'0x00',
'lcs_event_status':'0x00',
'streetlight':'0x00',
'temp_notify':'0x00',
'stlt_blk_relay':'0x00',
'stlt_open_circuit':'0x00',
'stlt_lamp_fail':'0x00',
'stlt_day_burner':'0x00',
'stlt_cycling':'0x00',
'stlt_comm_fail':'0x00',
'stlt_lamp_pwr_too_high':'0x00',
'stlt_lamp_pwr_too_low':'0x00',
'esp_gen':'0x00',
'security_threshold':'0x00',
'lua_string':'0x00',
'stlt_inv_calendar':'0x00',
'stlt_inv_program':'0x00',
'stlt_calendar_change':'0x00',
'stlt_program_change':'0x00',
'power_mon_stream':'0x00',
'no_location':'0x00',
'no_gps_time':'0x00',
'location_update':'0x00',
'stlt_low_mains_volt':'0x00',
'stlt_high_mains_volt':'0x00',
'stlt_low_pf':'0x00',
'stlt_set_lamp':'0x00',
'high_temp':'0x00',
'esp_pub_cpp':'0x00',
'stlt_low_curr':'0x00',
'stlt_high_curr':'0x00',
'lcs_alarm_log':'0x00',
'meter_id':'0x00',
'master_meter':'0x00',
}

	#ap_rf_conn_loss <band_id> (band ids are: 0-900 MHz FHSS)
    #dhcp_highlow_alarm <type> (low to no_range: 1 to 4)
	#battery_capacity <type> (Faulty[0x20], Battery level critical[0x04]/low[0x8])
	#pb_tamper_trap <state> (0 = clear 1 = set)
	#master_meter_reg <bpd_mac_addr> <operation>
	#c1219_tbl_mon_v2 <status>:<time>:<tid>:<offset>:<length>
	#imu_data <bpd-mac> <pdu-data>
    #pri_event_trap <mask> (8 byte format 0x00:0x00...)
	#ev_event <type> (plug in to override off: 1 to 7)
	#lgyr_iec_event <event_data> (18 bytes 0x00:0x00...)
	#rsm_change_trap <mask> (disconnected to armed: 1 to 3)
	#route_conflict_trap <ip-prefix/len> <dst-mac> <nh-mac> [flags]
	#voltage_monitor_trap <0|1> <deci-volts> (0: volt sag, 1: volt swell)
    #power_mon_alarm <channel>:<set=1/clear=0>
	#c1219_event <status>:<time>
	#c1219_alarm <status>:<time>
	#dlms_push_data <status>:<time>


#Trap setup:
#TRAP_SERVER_IPV6 = 'fd34:fe56:7891:7e23:4a8:7e53:a48e:e474'   #Local Macbook Ethernet
#TRAP_LOG = "/tmp/trap_file.txt"

#CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:004f:8917'

#sendMode = "-d "

'''
#Set Trap server address:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap host_set fd34:fe56:7891:7e23:4a8:7e53:a48e:e474

#Set Trap listening port:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap port_set 647   #On Net Mgr on the NIC

#Set delay for trap message sent:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap delay authority_key_missing 0    #On Net Mgr on the NIC

#Service is started by: 
sudo ./net_trap -p 40600  fd34:fe56:7891:7e23:4a8:7e53:a48e:e474  >> /tmp/trap_file.txt   #On local mac on 4.6 branch.
 
#Force a trap event example:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap force authority_key_missing   #On Net Mgr on the NIC

#Monitoring the event:
/tmp/tail -f trap_file.txt

Received *test* trap id = 0x529, seq=15, bootcnt=85, confirm=yes at time Thu Sep  6 22:32:53 2018 UTC (rx time Thu Sep  6 22:33:02 2018 UTC)
     -> reason="Authority Key Missing Test Trap" subj_key_id="da:39:a3:ee:5e:6b:4b:0d:32:55:bf:ef:95:60:18:90:af:d8:07:09" from 00:13:50:05:00:69:ce:38

'''

#Iterate over Dictionary and process Trap triggering and verification.


###################################################################################

#retValue = nm_tail_file(TRAP_LOG)   #Flush initial value

sendMode = "-d "
#Call to initialize the server
Nm.nm_config_trap_server(sendMode, CPD_IPV6_AP, TRAP_SERVER_IPV6)

#Excecute the trap server tests
for key, value in trapsToTest.iteritems():
    print key + " corresponds to " + trapsToTest[key] + "\n"

    #Dummy read first
    #Nm.nm_tail_file(TRAP_LOG)

    ret = Nm.nm_force_trap_event(key, sendMode, CPD_IPV6_AP)
    print "Returned value of nm_force_trap_event is: \'%s\' \n" % ret

    time.sleep(10)
    retValue = Nm.nm_tail_file(TRAP_LOG, trapsToTest[key])

    print "Ret Value of parsing is: \'%s\' \n" % retValue
    if retValue == trapsToTest[key]:
        print key + " corresponds to " + "\'"+trapsToTest[key]+"\'" + " : PASSED!!!\n"
    else:
        print key + " corresponds to " + "\'"+trapsToTest[key]+"\'" + " : FAILED!!!\n"


