#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Joseph Nguyen 8-20-2018
#File: Test_Dut.py
#Base Python program to call and invoke net_mgr



#To execute from project's root directory: python -m sandbox.Test_Dut.py    (Where package name is 'sandbox')
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
    NET_MGR_PATH = pwd + '/net_mgr'
elif platform == "linux2":                  #Raspberry Pi
    NET_MGR_PATH = pwd + '/arm_net_mgr/net_mgr'

print "Operation System and Net_Mgr Path are: %s:%s\n" % (platform, NET_MGR_PATH)

sendMode = '-d'  # via corp network & AP

IPV6 = CPD_IPV6_AP
BPD_DUT = BPD1_BRICK_MAC_ID

count = 0
class Test_Dut(unittest.TestCase):
    count = count +1

    def setUp(self):
        ########################################################################################################################
        """
        # Upload Operator cert test:
        op_x509_path = CERTS_PATH + OP_CERT
        print "Uploading OP Cert...\n"
        Nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, op_x509_path)

        # Upload ECBOCA cert test:
        ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
        print "Uploading ECBOCA cert...\n"
        Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, ecboca_x509_path)

        # Upload NMenity cert test:
        dl_x509_path = CERTS_PATH + SUB_NM_CERT
        print "Uploading NMenity Cert...\n"
        Nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, dl_x509_path)

        # Upload DLCA cert test:
        dl_x509_path = CERTS_PATH + SWENG_DLCA_2019
        print "Uploading DLCA Cert...\n"
        Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)

        # Upload DL cert test:
        dl_x509_path = CERTS_PATH + DL_CERT_CPD
        print "Uploading DL Cert...\n"
        Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)

        # Check cert chain node:
        print "Check Certs chains...\n"
        chain = Nm.nm_cert_own(sendMode, CPD_IPV6_AP)

        # Check valid certs chain ownership:
        chain.rstrip('\r\n')
        ret = Nm.nm_check_valid_chain(chain)
        print ("Output of valid cert check = %r \n" % ret)

        # Delete Operator cert and all subordinate certs:
        print "Deleting Op cert and subordinates...\n"
        Nm.nm_certs_delete_op(sendMode, CPD_IPV6_AP)
          #Upload ECBOCA cert test:
        #ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
        #print "Uploading ECBOCA cert...\n"
        #Nm.nm_upload_op_cert(sendMode, IPV6, ecboca_x509_path)

        #Upload NMenity cert test:
        #dl_x509_path = CERTS_PATH + SUB_NM_CERT
        #print "Uploading NMenity Cert...\n"
        #Nm.nm_upload_op_cert(sendMode, IPV6, dl_x509_path)

        #These next 2 are done as part of DL cert generation
        #Upload DLCA cert test:
        #dl_x509_path = CERTS_PATH + SWENG_DLCA_2019
        #print "Uploading DLCA Cert...\n"
        #Nm.nm_upload_dl_cert(sendMode, IPV6, dl_x509_path)

        #Next would be to upload mintedDL cert....

        #Check Certs Ownership level of device:
        #print "Validating & Checking certs ownership on devices... \'%s\'" % BPD1_IPV6_AP
        #Nm.nm_validate_certs_ownership(sendMode, BPD1_IPV6_AP, FULLY_DL_CHAINED_CERTS)

        #print "Validating & Checking certs ownership on devices... \'%s\'" % BPD2_IPV6_AP
        #Nm.nm_validate_certs_ownership(sendMode, BPD2_IPV6_AP, FULLY_DL_CHAINED_CERTS)
        """
        pass

    def test00_Preliminary_Requesites_Check(self):
        print "Get Image List...\n"
        Nm.nm_get_image_list(sendMode, CPD_IPV6_AP)

        #get version str on device
        print "Get Version Str...\n"
        Nm.nm_get_version_str(sendMode, CPD_IPV6_AP)


        # Configure CPD to be able to proxy for BPDS: :
        print "Configuring CPD for proper Proxy Mode on behalf of BPD...\n"
        Nm.nm_configure_cpd(sendMode, CPD_IPV6_AP)

        #Display lls_nodeq:
        print "Getting Link Layer Nodeq for the CPD and BPDs...\n"
        rc = Nm.nm_show_BPD_LLS_Nodes(sendMode, CPD_IPV6_AP)

        # Get Random 5-digits Required ID to start communication
        reqId = Nm.random_with_N_digits(5)
        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
        IPV6 = CPD_IPV6_AP
        timeOut = 30
        replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
        replyType2 = '03'  # HMAC, ShA256 for secured send comands

        print "Validating & Checking certs ownership on devices... \'%s\'\n" % CPD_IPV6_AP
        rc = Nm.nm_validate_certs_ownership(sendMode, CPD_IPV6_AP, FULLY_DL_CHAINED_CERTS)
        self.assertTrue('PASSED' in rc, "FAILED Certs Chain Verification")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

    """
    BPD_ARRAY = [BPD1_IPV6_AP, BPD2_IPV6_AP]
    for bpd_ipv6 in BPD_ARRAY:
    
        # Establihsing ALS connection and sendig first command via secured ALS
        (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, bpd_ipv6, timeOut=60, reqId=12345, \
                                                               replyType=5, replyType2='03', blobFileIn=CERTS_PATH + BLOB_FILE, privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)
    
        # Making a second secured command request via ALS
        cmdString = " certs esdump 4 "
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, bpd_ipv6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
    
        #Removing OP cert:
        #print "Removing OP cert....\n"
        #Nm.nm_remove_cert(sendMode, IPV6, '1025')
    
        ret = Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, bpd_ipv6)
    
    
    ########################################################################################################################
    
    #Upload Operator cert test:
    op_x509_path = CERTS_PATH + OP_CERT
    print "Uploading OP Cert...\n"
    Nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, op_x509_path)
    
    #Upload ECBOCA cert test:
    ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
    print "Uploading ECBOCA cert...\n"
    Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, ecboca_x509_path)
    
    
    #Upload NMenity cert test:
    dl_x509_path = CERTS_PATH + SUB_NM_CERT
    print "Uploading NMenity Cert...\n"
    Nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, dl_x509_path)
    
    #Upload DLCA cert test:
    dl_x509_path = CERTS_PATH + SWENG_DLCA_2019
    print "Uploading DLCA Cert...\n"
    Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)
    
    #Upload DL cert test:
    dl_x509_path = CERTS_PATH + DL_CERT_CPD
    print "Uploading DL Cert...\n"
    Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)
    
    
    #Check cert chain node:
    print "Check Certs chains...\n"
    chain = Nm.nm_cert_own(sendMode, CPD_IPV6_AP)
    
    #Check valid certs chain ownership:
    chain.rstrip('\r\n')
    ret = Nm.nm_check_valid_chain(chain)
    print ("Output of valid cert check = %r \n" % ret)
    
    #Delete Operator cert and all subordinate certs:
    print "Deleting Op cert and subordinates...\n"
    Nm.nm_certs_delete_op(sendMode, CPD_IPV6_AP)
    

    ################################################################################
    #Dump Cert Cache and returning a cert cache text table as a list

    
    certs_list = Nm.nm_dump_cert_cache(sendMode, CPD_IPV6_AP)
    #print "certs output: ", certs_list
    #print '{:s}'.format(certs_list)

    #Load output Cert Cache table into a list
    certs_array = []
    lines =  certs_list.split('\n')    #split by rows
    for rows in lines:
        elements =  rows.split('\t')
        print elements
        certs_array.append(elements)

    for e in certs_array:
        print e

    """

    def test01_cosem_obis_get_fw_version(self):
        #####################################################################################
        #Begin of BPD-CPD Security unit test DUT

        BPD_DUT = BPD1_BRICK_MAC_ID

        #*********************************************************************************************#
        #Test #1: Sending COSEM/OBIS formatted command to BPD to get version
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

        #print "Check 'nlog show dev' should see: \n"
        #print "raw tx [78]: 09 d3 2b 0f db 00 4d 00 00 00 01 00 78 00 01 00 3d e1 40 00 56 ce 01 01 08 49 54 52 63 00 00 00 00 01 08 49 54 55 43 1b ad a5 51 01 0c 07 e2 09 1a ff 0b 14 0e 00 00 00 00 00 00 56 ce 00 01 01 01 00 01 00 01 00 02 00 ff 01 02 00 02 00"
        #print "\n"
        #print "raw rx [74]: 08 0f db 0f db 00 49 00 00 00 01 00 01 00 78 00 39 e2 00 00 56 ce 01 01 08 49 54 52 63 00 00 00 00 01 08 49 54 55 43 1b ad a5 51 01 0c 07 e1 05 01 01 01 0e 28 00 00 00 00 00 00 56 ce 00 01 01 01 00 01 00 09 04 4a 01 01 14"
        #print "\n"
        self.assertTrue(BPD_FW_VERSION in rc, "Did not get FW Version as expected")

    def test02_send_raw_payload_to_BPD(self):
        #************************************************************************************************#
        #Test #2: Send raw payload to the BPD:
        print "Sending Test PAYLOAD1 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD1)
        print "Response Data for BPD cmd Payload is: \n\%s\'\n" % rc
        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

    def test03_send_zero_bytes_payload_to_BPD(self):
        #************************************************************************************************#
        #Test #3: Test with zero byte length payload to BPD:
        #*************************************************************#
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


        """
        if(0):
            print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
            time.sleep(CPD_2_BPD_POLLING_INTERVAL)


            print "Sending Test PAYLOAD_MAX_VALID to BPD...\n"
            rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_MAX_VALID)
            self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

            print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
            time.sleep(CPD_2_BPD_POLLING_INTERVAL)


            print "Sending Test PAYLOAD_2048 to BPD...\n"
            rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_2048)
            self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")
        """

    def test06_load_CPD_2_BPD_secure_key(self):
        # ************************************************************************************************#
        # Test #6: Test ability to load and set default security key on CPD for BPD
        # *************************************************************#
        print "Uploading default security key for BPD to CPD...\n"
        #Inject default security key between CPD and BPD
        rc = Nm.nm_inject_security_key(sendMode, IPV6, BPD_DUT, DEFAULT_SECURITY_KEY, 1)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

    def test07_delete_CPD_2_BPD_secure_key(self):
        # ************************************************************************************************#
        # Test #7: Test ability to remove/ddete/ default security key on CPD for BPD
        # *************************************************************#
        print "Uploading default security key for BPD to CPD...\n"
        print "Trying to establish ALS to delete old key"
        # Establihsing ALS connection and sendig first command via secured ALS
        reqId = Nm.random_with_N_digits(5)
        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
        #IPV6 = CPD_IPV6_AP
        timeOut = 30
        replyType2 = '03'  # HMAC, ShA256 for secured send comands

        (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, IPV6, timeOut=60, reqId=12345, \
                                                               replyType=5, replyType2='03',
                                                               blobFileIn=CERTS_PATH + BLOB_FILE,
                                                               privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

        # Making a second secured command request via ALS
        cmdString = "  mac_secmib delete  " + str(BPD_DUT) + " 1"
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut, replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

        #Bug: FIRMW-19441
        rc = Nm.nm_show_mac_sec_key(sendMode, IPV6, BPD_DUT, 1)
        self.assertFalse('Key' in rc, "Key should of been deleted as expected, but delete is failing")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

    def test08_send_package_with_mac_security_enabled(self):
         # ************************************************************************************************#
         # Test #8: Test with Mac security enabled 1000 bytes length payload to BPD:
         # *************************************************************#
         print ("Re-infecting default secure key on CPD for BPD....\n")
         Nm.nm_inject_security_key(sendMode, IPV6, DEFAULT_SECURITY_KEY, 1)

         #Take a read of stats before send:
         print "lls_nodeq data send statistic before send....\n"
         Nm.nm_check_lls_enabled(sendMode, IPV6)

         print "Sending Test PAYLOAD_1000 to BPD...\n"
         rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1000)
         self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

         print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
         time.sleep(CPD_2_BPD_POLLING_INTERVAL)

         # Take a read of stats after send:
         print "lls_nodeq data send statistic before send....\n"
         Nm.nm_check_lls_enabled(sendMode, IPV6)

    print "Class Test_Dut being called \'%d\' time(s)...\n" % count

########################################################################################################################
if __name__ == '__main__':
    unittest.main()

