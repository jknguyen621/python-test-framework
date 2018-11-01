#!/usr/bin/python

# Author: Joseph Nguyen 8-20-2018
# File: Test_Dut.py
# Base Python program to call and invoke net_mgr


# To execute from project's root directory: python -m sandbox.Test_Dut.py    (Where package name is 'sandbox')
from lib.nm_header import *
import lib.Nm as Nm
import time
import unittest

LOOP_MAX = 1

import os

pwd = os.getcwd()
print "Current Working Direcgtory %s\n" % (pwd)

NET_MGR_PATH = ''
from sys import platform

if platform == "darwin" or platform == "linux":
    NET_MGR_PATH = pwd + '/mac_tools/net_mgr'
elif platform == "linux2":  # Raspberry Pi
    NET_MGR_PATH = pwd + '/arm_tools/net_mgr'

print "Operation System and Net_Mgr Path are: %s:%s\n" % (platform, NET_MGR_PATH)

#sendMode = '-d'  # via corp network & AP

sendMode = '-g -d' # via FSU

IPV6 = CPD_IPV6_FSU  #CPD_IPV6_AP
BPD_DUT = BPD2_BRICK_MAC_ID


class Test_Dut(unittest.TestCase):
    sendMode = '-g -d'  #//via FSU
    # sendMode = '-d'     #via corp network & AP

    ########################################################################################################################

    # device discovery
    # print "Neighbor Discovery...\n"
    # Nm.nm_device_discovery('-i', CPD_MAC_ID)

    # Check nodeq 0
    # print "Check Nodeq...\n"
    # Nm.nm_nodeq_x('-i', '0')

    # Removing discovery for now, based on lls_nodeq show all for BPD to show up on CPD.

    # check image list on device
    print "Get Image List...\n"
    #Nm.nm_get_image_list(sendMode, IPV6)

    # get version str on device
    print "Get Version Str...\n"
    #Nm.nm_get_version_str(sendMode, IPV6)

    # Configure CPD to be able to proxy for BPDS: :
    #Nm.nm_configure_cpd(sendMode, IPV6, BPD_DUT)

    # Get Random 5-digits Required ID to start communication
    reqId = Nm.random_with_N_digits(5)
    blobFileIn = CERTS_PATH + BLOB_FILE
    privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
    #IPV6 = CPD_IPV6_AP
    timeOut = 30
    replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
    replyType2 = '03'  # HMAC, ShA256 for secured send comands

    

    
    '''
    # print "Validating & Checking certs ownership on devices... \'%s\'" % BPD2_IPV6_AP
    # Nm.nm_validate_certs_ownership(sendMode, BPD2_IPV6_AP, FULLY_DL_CHAINED_CERTS)

    print "Validating & Checking certs ownership on devices... \'%s\'" % IPV6
    #Nm.nm_validate_certs_ownership(sendMode, IPV6, FULLY_DL_CHAINED_CERTS)

    

    # Establihsing ALS connection and sendig first command via secured ALS
    (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode,IPV6, timeOut=60, reqId=12345, \
                                                               replyType=5, replyType2='03', blobFileIn=CERTS_PATH + BLOB_FILE, privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

    #seqNum = seqNum + 15
    # Making a second secured command request via ALS
    cmdString = " certs esdump 4 "
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

    CPD_CERTS_PATH = "/home/pi/python-test-framework/certs/CPD_Certs/"
    CPD_OP_CERT = "01_CPD_OPERATOR.x509"
    CPD_DLCA_CERT = "02_CPD_DLCA.x509"
    CPD_DL_CERT = "03_CPD_DL.x509"
    
    #Removing DL cert:#1281, #1282
    print "Removing DL cert 1281....\n"
    #Nm.nm_remove_cert(sendMode, IPV6, '1281')
    seqNum = seqNum + 15
    
    privateID = 1282
    cmdString = " certs erase " + str(privateID)
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    
    print "Removing DL cert 1282....\n"
    #Nm.nm_remove_cert(sendMode, IPV6, '1282')
    
    seqNum = seqNum + 15
    privateID = 1281
    cmdString = " certs erase " + str(privateID)
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

    
    
    #Removing DLCA cert: #1283
    print "Removing DLCA cert....\n"
    #Nm.nm_remove_cert(sendMode, IPV6, '1025')
    
    seqNum = seqNum + 15
    privateID = 1283
    cmdString = " certs erase " + str(privateID)
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    
    
    #Removing OP cert:  #1027
    print "Deleting Op cert and subordinates...\n"
    #Nm.nm_certs_delete_op(sendMode, IPV6)
    seqNum = seqNum + 15
    cmdString = " certs delete_op"
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    '''
    """
    seqNum = seqNum + 15
    
    print "Deleting NMENITY Cert...\n"
    #Nm.nm_certs_delete_op(sendMode, IPV6)
    seqNum = seqNum + 15
    privateID = "0x200010"
    cmdString = " certs erase " + str(privateID)
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    seqNum = seqNum + 15
    
    print "Deleting EBOCA CERT...\n"
    #Nm.nm_certs_delete_op(sendMode, IPV6)
    seqNum = seqNum + 15
    privateID = "0x20000f"
    cmdString = " certs erase " + str(privateID)
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    """
    #seqNum = seqNum + 15
    #ret = Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6)

    

################################################################################   
    def test_register_40_Devices(self):
        #"nm_trap force i5s_reg " + BPD2_BRICK_MAC_ID + " " + SST2 + " " + "04010a0c 101112131415161718192021222324"
        TEST_SST = "4954554300e4e2"
        TEST_BPD ="00:07:81:43:00:e4:e2:"
        for i in range(1, 41):
            cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + "nm_trap force i5s_reg " + TEST_BPD+str(i) + " " + TEST_SST+str(i) + " " + "04010a0c 101112131415161718192021222324"
            Nm.processCmd(cmd)
            time.sleep(3)

########################################################################################################################

if __name__ == '__main__':
    ut = unittest.main()
    ut = Test_Dut()
    #Test_Dut.test_cosem_obis_get_fw_version()
    #Test_Dut.test_send_raw_payload_to_BPD()
    #Test_Dut.test_send_various_size_payloads_to_BPD()