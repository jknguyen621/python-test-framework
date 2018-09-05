#!/usr/bin/python
#Author: Joseph Nguyen 8-20-2018
#Base Python program to call and invoke net_mgr
#File: loopTest.py
    
#import pexpect
import time 
import sys
import os
import string

LOOP_MAX = 1 
NET_MGR_PATH = '/Users/jnguyen/test-framework/tools/net_mgr'
#NET_MGR_PATH = '//home//pi//net_mgr//net_mgr'
CPD_MAC_ID = '00:13:50:05:00:69:ce:38'
CPD_IPV6_FSU = 'fe80::213:5005:0069:ce38'


BPD_MAC_ID = ''

#child = pexpect.spawn(NET_MGR_PATH  + ' -i mlme_disc_mac 00:13:50:05:00:69:ce:38')
#child.logfile = open("/tmp/loopLog", "w")
#child.expect('Ok')

#child.sendline(NET_MGR_PATH + ' -i nodeq 0')
#resp = child.expect(['00:13:50:05:00:69:ce:38', 'Node Queue. 1 total nodes', pexpect.EOF], timeout=10)

#child.expect('(^.*[0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}).*$')
#child.expect(pexpect.EOF)
#print(child.before)
#child.expect('\r\n\r\n00:13:50:05:00:69:ce:38')
#print child.read(size=-1)

#********************* COMMANDS ***************************************#
discover = NET_MGR_PATH + ' -i mlme_disc_mac ' + CPD_MAC_ID

nodeq0 = NET_MGR_PATH + ' -i nodeq 0'

get_image_list =  NET_MGR_PATH + ' -g -d ' + CPD_IPV6_FSU + ' image list'

dump_certs = NET_MGR_PATH + ' -g -d ' + CPD_IPV6_FSU + ' certs sdump 4'
#**********************************************************************#
for x in range(0, LOOP_MAX):
    print ("\n========================================\n")
    print ("LOOP #: " + '{:3d}'.format(x))
    
    print "Doing Discovery: " + '{:s}'.format(discover)
    os.system(discover)
    
    print "Checking Nodeq 0: " + '{:s}'.format(nodeq0)
    os.system(nodeq0)
    
    print "Checking image list on CPD: : " + '{:s}'.format(get_image_list)
    os.system(get_image_list)

    print "Checking certs on  CPD: : " + '{:s}'.format(dump_certs)
    os.system(dump_certs)
