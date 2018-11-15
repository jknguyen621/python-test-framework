#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Joseph Nguyen 8-20-2018
# File: Test_Security_TestCases.py
# Base Python program to call and invoke net_mgr


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
    NET_MGR_PATH = pwd + '/nm'                 #'/mac_tools/net_mgr'
elif platform == "linux2":  # Raspberry Pi
    NET_MGR_PATH = pwd + '/Nm'   #''/arm_tools/net_mgr'

print "Operation System and Net_Mgr Path are: %s:%s\n" % (platform, NET_MGR_PATH)

sendMode = '-g -d'  # via FSU, locally
#sendMode = '-d'  # via corp network & AP

#IPV6 = CPD1_IPV6_AP
#BPD_DUT = BPD1_BRICK_MAC_ID  # BPD1_BRICK_MAC_ID


class Test_Security(unittest.TestCase):

    def setUp(self):
        pass

    def test00_Preliminary_Requesites_Check(self):
        IPV6 = CPD2_IPV6_FSU #CPD1_IPV6_AP
        BPD_DUT = BPD2_BRICK_MAC_ID  # BPD1_BRICK_MAC_ID

        print "Get Image List...\n"
        Nm.nm_get_image_list(sendMode, IPV6)

        # get version str on device
        print "Get Version Str...\n"
        Nm.nm_get_version_str(sendMode, IPV6)

        # Configure CPD to be able to proxy for BPDS: :
        print "Configuring CPD for proper Proxy Mode on behalf of BPD...\n"
        Nm.nm_configure_cpd(sendMode, IPV6, BPD_DUT)

        # Display lls_nodeq:
        print "Getting Link Layer Nodeq for the CPD and BPDs...\n"
        rc = Nm.nm_show_BPD_LLS_Nodes(sendMode, IPV6)

        # Get Random 5-digits Required ID to start communication
        reqId = Nm.random_with_N_digits(5)
        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
        #IPV6 = CPD_IPV6_AP
        timeOut = 30
        replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
        replyType2 = '03'  # HMAC, ShA256 for secured send comands

        print "Validating & Checking certs ownership on devices... \'%s\'\n" % IPV6
        rc = Nm.nm_validate_certs_ownership(sendMode, IPV6, FULLY_DL_CHAINED_CERTS)
        self.assertTrue('PASSED' in rc, "FAILED Certs Chain Verification")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Clear both the event and nlog for APP layer secure events:
        rc = Nm.nm_clear_logs(sendMode, IPV6)
        print rc


    def test01_cosem_obis_get_fw_version(self):
        #####################################################################################
        # Begin of BPD-CPD Security unit test DUT

        # *********************************************************************************************#
        # Test #1: Sending COSEM/OBIS formatted command to BPD to get version
        # Request BPD's FW Version
        obisInvokeID = 22222

        obisCommand = OBIS_FW_VERSION
        print "REQUEST BPD FW VERSION\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, BPD_DUT, IPV6)
        obisInvokeID += 1

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Get resonse:
        rc = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
        print "Response Data for BPD's FW Version is: \n\%s\'\n" % rc

        # print "Check 'nlog show dev' should see: \n"
        # print "raw tx [78]: 09 d3 2b 0f db 00 4d 00 00 00 01 00 78 00 01 00 3d e1 40 00 56 ce 01 01 08 49 54 52 63 00 00 00 00 01 08 49 54 55 43 1b ad a5 51 01 0c 07 e2 09 1a ff 0b 14 0e 00 00 00 00 00 00 56 ce 00 01 01 01 00 01 00 01 00 02 00 ff 01 02 00 02 00"
        # print "\n"
        # print "raw rx [74]: 08 0f db 0f db 00 49 00 00 00 01 00 01 00 78 00 39 e2 00 00 56 ce 01 01 08 49 54 52 63 00 00 00 00 01 08 49 54 55 43 1b ad a5 51 01 0c 07 e1 05 01 01 01 0e 28 00 00 00 00 00 00 56 ce 00 01 01 01 00 01 00 09 04 4a 01 01 14"
        # print "\n"
        self.assertTrue(BPD_FW_VERSION in rc, "Did not get FW Version as expected")

        # Get event log for APP layer secure events:
        rc = Nm.nm_event(sendMode, IPV6)
        print rc

    def test02_send_raw_payload_to_BPD(self):
        # ************************************************************************************************#
        # Test #2: Send raw payload to the BPD:
        print "Sending Test PAYLOAD1 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD1)
        print "Response Data for BPD cmd Payload is: \n\%s\'\n" % rc
        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")


    def test03_send_zero_bytes_payload_to_BPD(self):
        # ************************************************************************************************#
        # Test #3: Test with zero byte length payload to BPD:
        # *************************************************************#
        print "Sending Test PAYLOAD_ZERO to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_ZERO)
        print "Response Data for BPD cmd Payload of zero is: \n\%s\'\n" % rc
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

    def test04_send_1000_bytes_payload_to_BPD(self):
        # ************************************************************************************************#
        # Test #4: Test with 1000 bytes length payload to BPD:
        # *************************************************************#
        print "Sending Test PAYLOAD_1000 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1000)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

    def test05_send_1001_bytes_payload_to_BPD(self):
        # ************************************************************************************************#
        # Test #5: Test with 1001 bytes length payload to BPD:
        # *************************************************************#
        print "Sending Test PAYLOAD_1001 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1001)
        self.assertTrue('Erroneous request' in rc, "Did not get received 'Erroneous Request' message as expected")

    def test06_load_CPD_2_BPD_secure_key(self):
        # ************************************************************************************************#
        # Test #6: Test ability to load and set default security key on CPD for BPD
        # *************************************************************#
        Nm.nm_clear_logs(sendMode, IPV6)

        print "Uploading default security key for BPD to CPD...\n"
        # Inject default security key between CPD and BPD
        rc = Nm.nm_inject_security_key(sendMode, IPV6, BPD_DUT, DEFAULT_SECURITY_KEY, 1)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

    def test07_delete_CPD_2_BPD_secure_key(self):
        # ************************************************************************************************#
        # Test #7: Test ability to remove/ddete/ default security key on CPD for BPD
        # *************************************************************#
        print "Showing default security key for BPD to CPD...\n"

        Nm.nm_clear_logs(sendMode, IPV6)

        rc = Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)
        self.assertTrue('Key' in rc, "Secured Key for BPD should have been loaded...\n")

        print "Trying to establish ALS to delete old key"
        # Establihsing ALS connection and sendig first command via secured ALS
        reqId = Nm.random_with_N_digits(5)
        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
        # IPV6 = CPD_IPV6_AP
        timeOut = 30
        replyType2 = '03'  # HMAC, ShA256 for secured send comands

        (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, IPV6, timeOut=60, reqId=12345, \
                                                               replyType=5, replyType2='03',
                                                               blobFileIn=CERTS_PATH + BLOB_FILE,
                                                               privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

        # Making a second secured command request via ALS
        cmdString = "  mac_secmib delete  " + str(BPD_DUT) + " 1"
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

        # Bug: FIRMW-19441
        rc = Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)
        self.assertFalse('Key' in rc, "Key should of been deleted as expected, but delete is failing")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

    def test08_send_package_with_mac_security_enabled(self):
        # ************************************************************************************************#
        # Test #8: Test with Mac security enabled 1000 bytes length payload to BPD:
        # *************************************************************#
        Nm.nm_clear_logs(sendMode, IPV6)

        print ("Re-infecting default secure key on CPD for BPD....\n")
        Nm.nm_inject_security_key(sendMode, IPV6, DEFAULT_SECURITY_KEY, 1)

        # Take a read of stats before send:
        print "lls_nodeq data send statistic before send....\n"
        Nm.nm_check_lls_enabled(sendMode, IPV6)

        print "Sending Test PAYLOAD_1000 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1000)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        # TODO: Once Security is fully implemented,
        # Need to revisit this test and check and assert for SecLevel=6
        # without requiring the [SecMode][Index] options.

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Take a read of stats after send:
        print "lls_nodeq data send statistic before send....\n"
        rc = Nm.nm_check_lls_enabled(sendMode, IPV6)
        self.assertTrue(BPD_DUT.lower() in rc, 'Did not get BPD under test Mac ID in lls_nodeq show all')

        #NOTE: Loac/inject security is no longer supported if Security is enable, since A3-Integration
        # Show current Secure Key:
        #print "Display current loaded secured key for BPD on CPD\n"
        #rc = Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)
        #self.assertTrue(DEFAULT_SECURITY_KEY.lower() in rc,
                        #'Did not get DEFAULT_SECURITY_KEY in  mac_secmib show BPD_DUT')

        # Get event log for APP layer secure events:
        rc = Nm.nm_event(sendMode, IPV6)     #Note: lls cmd is a link layer send, so wont see

    def test09_test_send_secure_mode_1K_payload(self):
        # ************************************************************************************************#
        # Test #9: Test with Mac security enabled and Sec Mode=6 SAFE_SECURED_PAYLOAD  length payload to BPD:
        # This test will not work after A3-Integration, since no more manual key injection
        # *************************************************************#
        Sec_Mode = 6
        index = 1

        Nm.nm_clear_logs(sendMode, IPV6)

        #rc1 = Nm.nm_get_TxFrameCounter(sendMode, IPV6, BPD_DUT, 1)
        #print "Tx Frame Counter before command is: \'%s\' \n" % rc1

        #TODO: Figure out how to do security Key after A3-Integration, for the time, will use unsercure send.
        #print "Testing BPD secure send raw payload at LLS level, using key and Sec Mode set to 6 for the time being...\n"
        #rc = Nm.nm_send_secured_CPD_cmd(sendMode, IPV6, BPD_DUT, SAFE_SECURED_PAYLOAD, Sec_Mode, index)

        print "Testing BPD secure send raw payload at LLS level, using key and Sec Mode set to 6 for the time being...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, SAFE_SECURED_PAYLOAD)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        # Lls Rx Cmd: Len = 942, SecLvl = 6

        # NOTE: Expect to see on COSEM DevBench for BPD's log as:

        # 2018/10/03 09:16:48.003 => Lls Rx BLS
        # 2018/10/03 09:16:48.065 => Lls Lw Pending Cmd
        # 2018/10/03 09:16:48.065 => MAC Rx Valid Frame Len: 966
        # 2018/10/03 09:16:48.128 => MAC Rx Ack Sent
        # 2018/10/03 09:16:48.190 => Lls Rx Cmd: Len = 934, SecLvl = 6
        # 2018/10/03 09:17:17.911 => LLS Lw: chan=39, dur=6.8ms, freqVar=0.0ppm, freqErr=0.1ppm
        # 2018/10/03 09:17:17.911 => MAC Rx Valid Frame Len: 18

        print "Please Manually Check COSEM DevBench for proper SecLevel...\n"
        # TODO: Once Security is fully implemented and BPD's events are supported,
        # need to detect, SecLevel=6 and check and assert accorindgly.
        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # NOTE:TxFrameCounter will only be increasing for MAC and App layer requests.
        #rc2 = Nm.nm_get_TxFrameCounter(sendMode, IPV6, BPD_DUT, 1)
        #print "Tx Frame Counter before command is: \'%s\' \n" % rc2
        #self.assertTrue(rc2 > rc1, "BPD's Tx Frame Counter didn't increment as expected")

        # NOTE: Can only be seen within COSEM DevBench log for now.

    def test10_test_send_secure_mode_cosem_obis_cmd(self):
        # ************************************************************************************************#
        # Test #10: Test with COSEM OBIS command via secured channel
        # NOTE: THis is an APP level security testing.
        # Testing security enforcement down the stack.
        # *************************************************************#

        Nm.nm_clear_logs(sendMode, IPV6)

        # NOTE: Loac/inject security is no longer supported if Security is enable, since A3-Integration
        #print("Displaying the current BPD node security key...\n")
        #Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)

        print "Testing BPD COSEM/OBIS command send with temp default secure key...\n"
        obisInvokeID = 5555

        rc1 = Nm.nm_get_TxFrameCounter(sendMode, IPV6, BPD_DUT, 1)
        print "Tx Frame Counter before command is: \'%s\' \n" % rc1

        obisCommand = OBIS_FW_VERSION  # Not secured? OBIS_MAC
        print "OBIS REQUEST FOR BPD MAC ID\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, BPD_DUT, IPV6)
        obisInvokeID += 1

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        #NOTE:TxFrameCounter will only be increasing for MAC and App layer requests.
        rc2 = Nm.nm_get_TxFrameCounter(sendMode, IPV6, BPD_DUT, 1)
        print "Tx Frame Counter before command is: \'%s\' \n" % rc2
        self.assertTrue(rc2 > rc1, "BPD's Tx Frame Counter didn't increment as expected")

        # In COSEM DevBench, expecting to see this:
        # Lls Rx Cmd: Len = 90, SecLvl = 6

        # Get resonse:
        rc = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
        print "Response Data for BPD's FW Version is: \n\%s\'\n" % rc

        # Sleep a little longer to ensure we get the expected event in the event log.
        print "Sleep a little longer to ensure robustness of respond messages..."
        time.sleep(60)

        # Get event log for APP layer secure events:
        rc = Nm.nm_event(sendMode, IPV6)
        print rc
        self.assertTrue('sec_level=6' in rc,
                        "Did not get proper security level in the event log 'sec_level=6' as expected")

    def test11_send_lls_nodeq_cmd_with_payload_to_request_FW_Version(self):
        # ************************************************************************************************#
        # Test #11: Test using lls_nodeq cmd at the Link Layer with payload that requests FW version
        # Verify imu_data last_read and fw version read back.
        # *************************************************************#

        Nm.nm_clear_logs(sendMode, IPV6)

        print "Testing BPD send raw payload for FW Version at LLS level...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_FW_VER)

        print("Displaying the current BPD node security key...\n")
        Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)


        # Take a read of stats after send:
        print "lls_nodeq data send statistic before send....\n"
        rc = Nm.nm_check_lls_enabled(sendMode, IPV6)
        self.assertTrue(BPD_DUT.lower() in rc, 'Did not get BPD under test Mac ID in lls_nodeq show all')

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)


        # Get resonse:
        rc = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
        print "Response Data for BPD's FW Version is: \n\%s\'\n" % rc

        self.assertTrue(BPD_FW_VERSION in rc, "Did not get FW Version as expected")

    if (0):
        def test99_test_new_feature(self):
            rc = Nm.nm_get_TxFrameCounter(sendMode, IPV6, BPD_DUT, 1)
            print "Inside test99, TxFrameCounter is:  \'%s\' \n" % rc


########################################################################################################################
if __name__ == '__main__':
    unittest.main()
