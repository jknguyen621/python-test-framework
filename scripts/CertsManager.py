#!/usr/bin/python

# Author: Joseph Nguyen 8-20-2018
# File: Certs_Manager.py
# Base Python program to call and invoke net_mgr


# To execute from project's root directory: python -m scripts.CertsManager.py    (Where package name is 'scripts')
from lib.nm_header import *
import lib.Nm as Nm
import time
import unittest

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

# sendMode = '-d'  # via corp network & AP

sendMode = '-g -d'  # via FSU

IPV6 = CPD_IPV6_FSU  # CPD_IPV6_AP
BPD_DUT = BPD1_BRICK_MAC_ID #BPD2_BRICK_MAC_ID


class CertsManager(unittest.TestCase):
    sendMode = '-g -d'  # //via FSU
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
    #print "Get Image List...\n"
    # Nm.nm_get_image_list(sendMode, IPV6)

    # get version str on device
    #print "Get Version Str...\n"
    # Nm.nm_get_version_str(sendMode, IPV6)

    # Configure CPD to be able to proxy for BPDS: :
    #Nm.nm_configure_cpd(sendMode, IPV6, BPD_DUT)

    # Get Random 5-digits Required ID to start communication
    reqId = Nm.random_with_N_digits(5)
    blobFileIn = CERTS_PATH + BLOB_FILE
    privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
    timeOut = 30
    replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
    replyType2 = '03'  # HMAC, ShA256 for secured send comands

    # print "Validating & Checking certs ownership on devices... \'%s\'" % BPD2_IPV6_AP
    # Nm.nm_validate_certs_ownership(sendMode, BPD2_IPV6_AP, FULLY_DL_CHAINED_CERTS)

    ####################################################################################################################
    #REMOVING OLD OP's Path chained certs(DL, DLCA, and OP), optionally NMENITY and EBOCA too
    ####################################################################################################################
    def test_removing_OP_chained_path_certs(self):
        # Establihsing ALS connection and sendig first command via secured ALS
        (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, IPV6, timeOut=60, reqId=12345, \
                                                               replyType=5, replyType2='03',
                                                               blobFileIn=CERTS_PATH + BLOB_FILE,
                                                               privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

        # seqNum = seqNum + 15
        # Making a second secured command request via ALS
        cmdString = " certs esdump 4 "
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)



        # Removing DL cert:#1281, #1282
        print "Removing DL cert 1281....\n"
        # Nm.nm_remove_cert(sendMode, IPV6, '1281')
        seqNum = seqNum + 15

        privateID = 1282
        cmdString = " certs erase " + str(privateID)
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

        print "Removing DL cert 1282....\n"
        # Nm.nm_remove_cert(sendMode, IPV6, '1282')

        seqNum = seqNum + 15
        privateID = 1281
        cmdString = " certs erase " + str(privateID)
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

        # Removing DLCA cert: #1283
        print "Removing DLCA cert....\n"
        # Nm.nm_remove_cert(sendMode, IPV6, '1025')

        seqNum = seqNum + 15
        privateID = 1283
        cmdString = " certs erase " + str(privateID)
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)

        # Removing OP cert:  #1027
        print "Deleting Op cert and subordinates...\n"
        # Nm.nm_certs_delete_op(sendMode, IPV6)
        seqNum = seqNum + 15
        cmdString = " certs delete_op"
        (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                                replyType2)
        print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
            seqNum, assocId, ss)
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

        #NOTE: if all failed, try app_sysvar delete:360  (the certs cache)

        Nm.nm_dump_cert_cache(sendMode, IPV6)


        print "Deleting out app_sysvar:360 for certs cache...\n"
        ID = 360
        Nm.nm_delete_sysvar(sendMode, IPV6, ID)

        Nm.nm_dump_cert_cache(sendMode, IPV6)

        seqNum = seqNum + 15
        ret = Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6)

    ########################################################################################################################

    def test_inject_OP_chained_path_certs(self):

        #Certs generated form i5sim V.
        CPD_CERTS_PATH = pwd + "/certs/CPD_Certs/"
        CPD_OP_CERT = "01_CPD_OPERATOR.x509"
        CPD_DLCA_CERT = "02_CPD_DLCA.x509"
        CPD_DL_CERT = "03_CPD_DL.x509"

        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE

        #Upload Operator cert test:
        op_x509_path = CPD_CERTS_PATH + CPD_OP_CERT
        print "Uploading OP Cert...\n"
        Nm.nm_upload_op_cert(sendMode, IPV6, op_x509_path)

        #Upload ECBOCA cert test:
        #ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
        #print "Uploading ECBOCA cert...\n"
        #Nm.nm_upload_dl_cert(sendMode, IPV6, ecboca_x509_path)


        #Upload NMenity cert test:
        #dl_x509_path = CERTS_PATH + SUB_NM_CERT
        #print "Uploading NMenity Cert...\n"
        #Nm.nm_upload_op_cert(sendMode, IPV6, dl_x509_path)

        #Upload DLCA cert test:
        dl_x509_path = CPD_CERTS_PATH + CPD_DLCA_CERT
        print "Uploading DLCA Cert...\n"
        Nm.nm_upload_dl_cert(sendMode, IPV6, dl_x509_path)

        #Upload DL cert test:
        dl_x509_path = CPD_CERTS_PATH + CPD_DL_CERT
        print "Uploading DL Cert...\n"
        Nm.nm_upload_dl_cert(sendMode, IPV6, dl_x509_path)

        #Sync certs write from temp to flash

        print "Sync Certs chains...\n"
        ret = Nm.nm_cert_sync(sendMode, IPV6)
        print ("Output of Sync Certs....= %r \n" % ret)

        #Check cert chain node:
        print "Check Certs chains...\n"
        chain = Nm.nm_cert_own(sendMode, IPV6)

        #Check valid certs chain ownership:
        chain.rstrip('\r\n')
        ret = Nm.nm_check_valid_chain(chain)
        print ("Output of valid cert check = %r \n" % ret)



    ################################################################################
    def test_dump_certs(self):
        # Dump Cert Cache and returning a cert cache text table as a list
        certs_list = Nm.nm_dump_cert_cache(sendMode, CPD_IPV6_AP)
        # print "certs output: ", certs_list
        # print '{:s}'.format(certs_list)

        # Load output Cert Cache table into a list
        certs_array = []
        lines = certs_list.split('\n')  # split by rows
        for rows in lines:
            elements = rows.split('\t')
            print elements
            certs_array.append(elements)

        for e in certs_array:
            print e

    def test_cosem_obis_get_fw_version(self):
        #####################################################################################
        # Begin of BPD-CPD Security unit test DUT

        BPD_DUT = BPD2_BRICK_MAC_ID

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

    def test_send_raw_payload_to_BPD(self):
        # ************************************************************************************************#
        # Test #2: Send raw payload to the BPD:
        print "Sending Test PAYLOAD1 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD1)
        print "Response Data for BPD cmd Payload is: \n\%s\'\n" % rc
        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

    def test_send_various_size_payloads_to_BPD(self):
        # ************************************************************************************************#
        # Test #3: Test with various length payload to BPD:
        # *************************************************************#
        print "Sending Test PAYLOAD_ZERO to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_ZERO)
        print "Response Data for BPD cmd Payload of zero is: \n\%s\'\n" % rc
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        print "Sending Test PAYLOAD_1000 to BPD...\n"
        rc = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1000)
        self.assertTrue('Ok' in rc, "Did not get 'OK' message as expected")

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        print "Sending Test PAYLOAD_1001 to BPD...\n"
        rc = retCode = Nm.nm_send_CPD_cmd(sendMode, IPV6, BPD_DUT, PAYLOAD_1001)
        self.assertTrue('Erroneous request' in rc, "Did not get received 'Erroneous Request' message as expected")


########################################################################################################################

if __name__ == '__main__':
    ut = unittest.main()
    ut = CertsManager()
    # CertsManagert.test_cosem_obis_get_fw_version()
    # CertsManager.test_send_raw_payload_to_BPD()
    # CertsManager.test_send_various_size_payloads_to_BPD()
    # CertsManager.test_removing_OP_chained_path_certs()
    # CertsManager.test_inject_OP_chained_path_certs()