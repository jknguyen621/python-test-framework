#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 7th, 2018
#File: trapTester.py

#from ..lib.nm_header import *
#import lib.Nm as Nm

import subprocess
import time
import os
import sys
import select
from pygtail import Pygtail    #download and install pygtail package under /Library/Python/2.7/site-packages
#Download pygtail at: https://github.com/bgreenlee/pygtail

pwd = os.getcwd()
print "Current Working Direcgtory %s\n" % (pwd)

NET_MGR_PATH = ''
from sys import platform
if platform == "darwin" or platform == "linux":
    NET_MGR_PATH = pwd + '/net_mgr'
elif platform == "linux2":                  #Raspberry Pi
    NET_MGR_PATH = pwd + '/arm_net_mgr/net_mgr'


""" 
Currently, to run this script, it is assumed you have setup a local net_trap server, IPV6, and port associated with it
as well as the path to log output. ie. /tmp/trap_file.txt

Call this program from project root directory: python -m miscellaneous.trapTester.py
"""
#List of traps that are currently testable via a net_mgr's nmtrap force command(only 18 out of 71 are testable this way.


trapsToTest = {
#'power_loss':'0xcf',
#'power_restore':'0xd0',
#'battery_off': '0x11f',
#'battery_on':'0x11e',
'battery_config_mismatched':'0x379',
}

"""
trapsToTest = {
'power_loss':'0xcf',
#'power_restore':'0xd0',
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

#Trap setup:
TRAP_SERVER_IPV6 = 'fd34:fe56:7891:7e23:4a8:7e53:a48e:e474'   #Local Macbook Ethernet
TRAP_LOG = "/tmp/trap_file.txt"

CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:0069:ce38'

sendMode = "-d "

'''
#Set Trap server address:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap host_set fd34:fe56:7891:7e23:4a8:7e53:a48e:e474

#Set Trap listening port:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap port_set 647   #On Net Mgr on the NIC

#Set delay for trap message sent:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap delay authority_key_missing 30    #On Net Mgr on the NIC

#Service is started by: 
sudo ./net_trap -p 647  fd34:fe56:7891:7e23:4a8:7e53:a48e:e474  >> /tmp/trap_file.tx   #On local mac on 4.6 branch.

#Force a trap event example:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap force authority_key_missing   #On Net Mgr on the NIC

#Monitoring the event:
/tmp/tail -f trap_file.txt

Received *test* trap id = 0x529, seq=15, bootcnt=85, confirm=yes at time Thu Sep  6 22:32:53 2018 UTC (rx time Thu Sep  6 22:33:02 2018 UTC)
     -> reason="Authority Key Missing Test Trap" subj_key_id="da:39:a3:ee:5e:6b:4b:0d:32:55:bf:ef:95:60:18:90:af:d8:07:09" from 00:13:50:05:00:69:ce:38

'''

#Iterate over Dictionary and process Trap triggering and verification.

#Routine to handle terminal commandline processing and returning error and actual terminal output, not exit code.
def processCmd(cmd, *argv):
    for arg in argv:
        print "another arg through *argv :", arg

    print ("Processing Command: \'%s\' \n" % cmd)
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    #print "command terminal output: \'%s\' \n" % str(out)
    return out

def nm_force_trap_event(trap):
    cmd = NET_MGR_PATH + " " + sendMode + " " + CPD_IPV6_AP + " " + "nm_trap force  " + str(trap)
    ret = processCmd(cmd)
    return ret

def nm_tail_file(filePath, expectedValue):
    exptedValue = "Received"
    exptedValue1 = "Received trap id = " + str(expectedValue)
    expectedValue2 = "Received *test* trap id = " + str(expectedValue)
    for line in Pygtail(filePath):
        sys.stdout.write(line)
        if exptedValue in line:
            myList = line.split('=')
            print myList
            myList2 = myList[1].split(',')
            actualValue = myList2[0].lstrip()
            print "Hex Value Received is: \'%s\' \n" % actualValue
            #break
            return actualValue
        else:
            pass



###################################################################################

#retValue = nm_tail_file(TRAP_LOG)   #Flush initial value

for key, value in trapsToTest.iteritems():
    print key + " corresponds to " + trapsToTest[key] + "\n"

    ret = nm_force_trap_event(key)
    time.sleep(3)
    retValue = nm_tail_file(TRAP_LOG, trapsToTest[key])

    print "Ret Value of parsing is: \'%s\' \n" % retValue
    if retValue == trapsToTest[key]:
        print key + " corresponds to " + "\'"+trapsToTest[key]+"\'" + " : PASSED!!!\n"
    else:
        print key + " corresponds to " + "\'"+trapsToTest[key]+"\'" + " : FAILED!!!\n"


