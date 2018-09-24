#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Nm_Tester.py

from lib.nm_header import *
from lib.utilities import *
import lib.Nm as Nm
import os
import time

from random import randint
global seqNum

filePath = "/tmp/pickleFile.myData"

if os.path.isfile(filePath):
    seqNum = read_data_from_file(filePath)
else:
    seqNum = 0

seqNum = int(seqNum)

#This is a break-out file, from the main section of Nm.py, to separate the testing portion for the library from the libary.
#As it's gotten too big to be part of the library.


print "Running nm.py module as script"
print "NIC info"
sendMode = '-d'

timeOut = 60
Nm.nm_discover_thy_neighbor(sendMode, CPD_MAC_ID, 30)

# Get Random 5-digits Required ID to start communication
reqId = Nm.random_with_N_digits(5)
blobFileIn = CERTS_PATH + BLOB_FILE
privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
IPV6 = CPD_IPV6_AP
replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
replyType2 = '03'  # HMAC, ShA256 for secured send comands

# Configure CPD to talk to BPD:
Nm.nm_configure_cpd(sendMode, IPV6)
#Nm.nm_configure_cpd(sendMode, BPD1_IPV6_AP)
#Nm.nm_configure_cpd(sendMode, BPD2_IPV6_AP)
#Nm.nm_restart_now(sendMode, IPV6)    #Dont want to restart now

#Check Certs Ownership level of device:
#print "Validating & Checking certs ownership on devices... \'%s\'" % BPD1_IPV6_AP
#Nm.nm_validate_certs_ownership(sendMode, BPD1_IPV6_AP, FULLY_DL_CHAINED_CERTS)

#print "Validating & Checking certs ownership on devices... \'%s\'" % BPD2_IPV6_AP
#Nm.nm_validate_certs_ownership(sendMode, BPD2_IPV6_AP, FULLY_DL_CHAINED_CERTS)

print "Validating & Checking certs ownership on devices... \'%s\'" % CPD_IPV6_AP
Nm.nm_validate_certs_ownership(sendMode, CPD_IPV6_AP, FULLY_DL_CHAINED_CERTS)


IPV6_ARRAY = [CPD_IPV6_AP]

for ipv6 in IPV6_ARRAY:

    # Establihsing ALS connection and sendig first command via secured ALS
    (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, ipv6, timeOut=60, reqId=12345, \
                                                           replyType=5, replyType2='03', blobFileIn=CERTS_PATH + BLOB_FILE, privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

    # Making a second secured command request via ALS
    cmdString = " certs esdump 4 "
    (seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, ipv6, timeOut,
                                                            replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
        seqNum, assocId, ss)

    # Get a list of Securit Association:
    sa_list = Nm.nm_get_secure_association_list(sendMode, IPV6)
    print "ALS ccurent Security Asscocation list is: \'%s\'\n"  % (sa_list)


    # Disable unsecured port for safety net during testing as a way to recover.
    # NOTE: if you use net_mgrS for connection, it will enable the unsecured port on Gen5 NIC.
    unsecureMode = 0  # DISABLED


    seqNum = seqNum + 11  #For some resason, when we start to disable unsecured port, seqNum increased by 11
    (seqNum, assocId, ss) = Nm.nm_conf_disable_unsecure(sendMode, seqNum, assocId, ss, unsecureMode, ipv6)

    # Set Link Layer Idle Timeout to 1 day:
    noOfDay = 1
    Nm.nm_conf_set_link_layer_idle_limit(sendMode, noOfDay, ipv6)

    # Set App Layer idle timeout to 1 day:
    Nm.nm_conf_set_app_layer_idle_limit(sendMode, noOfDay, ipv6)

    if(0):
        # show various types of certs:
        birthCert = Nm.nm_show_cert(sendMode, ipv6, 2)  # Birth
        print "BIRTH CERT: \n" + birthCert

        mfgCert = Nm.nm_show_cert(sendMode, ipv6, 3)  # MFG
        print "MFG CERT: \n" + mfgCert

    # Test MAC Layer Security with hardcoded CCM secret Alpha2 Integreation
    cmdString = ''
    if ipv6 == BPD1_IPV6_AP:
        Nm.nm_send_CPD_cmd(sendMode, ipv6, BPD1_BRICK_MAC_ID, PAYLOAD1)
        #cmdString = "-v lls_nodeq cmd " + BPD1_BRICK_MAC_ID + " " + PAYLOAD1
    elif ipv6 == BPD2_IPV6_AP:
        Nm.nm_send_CPD_cmd(sendMode, ipv6, BPD1_BRICK_MAC_ID, PAYLOAD2)
        #cmdString = "-v lls_nodeq cmd " + BPD2_BRICK_MAC_ID + " " + PAYLOAD2
    else:
        pass

    #ret = Nm.nm_get_BPD_response(sendMode, ipv6, BPD1_BRICK_MAC_ID)
    # Making a second secured command request via ALS
    #cmdString = "-t 20 -v lls_nodeq cmd " + BPD1_BRICK_MAC_ID + " " + PAYLOAD1

    #if ipv6 != CPD_IPV6_AP:
        #(seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, ipv6, timeOut,
        #                                                        replyType2)
        #print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
        #seqNum, assocId, ss)




#Disabling this for now, the return cache is huge, with all the certs text printed out.
#certsCache = Nm.nm_show_cert(sendMode, IPV6, 4) #Cert Cache
#print "CERTs CACHE: \n" + certsCache



#COSEM/OBIS commands testing to the BPDs
obisInvokeID = 11111

#BPD_ARRAY = [BPD1_IPV6_AP, BPD2_IPV6_AP]
BPD_ARRAY = [CPD_IPV6_AP]
if(1):
    for bpd_ipv6 in BPD_ARRAY:
        # Read BPD's FW Version
        obisCommand = OBIS_FW_VERSION
        print "READING BPD FW VERSION\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, bpd_ipv6)
        obisInvokeID += 1

        # Get resonse:
        res = Nm.nm_get_latest_IMU_data_response(sendMode, bpd_ipv6)
        print "Response Data for BPD's FW Version is: \n\%s\'\n" % res

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..."  % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Read BPD's Unix Time
        obisCommand = OBIS_UNIX_TIME
        print "READING BPD TIME\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, bpd_ipv6)
        obisInvokeID += 1

        # Get resonse:
        res = Nm.nm_get_latest_IMU_data_response(sendMode, bpd_ipv6)
        print "Response Data for BPD's Unix Time is: \n\%s\'\n" % res

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Read BPD's SN
        obisCommand = OBIS_SN
        print "READING BPD S/N\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, bpd_ipv6)
        obisInvokeID += 1

        # Get resonse:
        res = Nm.nm_get_latest_IMU_data_response(sendMode, bpd_ipv6)
        print "Response Data for BPD's SN is: \n\%s\'\n" % res

        print "Sleep for set CPD-2-BPD POLLING INTERVAL SETTING OF: \'%s\' seconds ..." % (CPD_2_BPD_POLLING_INTERVAL)
        time.sleep(CPD_2_BPD_POLLING_INTERVAL)

        # Read BPD's MAC ID
        obisCommand = OBIS_MAC
        print "READING BPD MAC ID\n"
        Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, bpd_ipv6)
        obisInvokeID += 1

        # Get resonse:
        res = Nm.nm_get_latest_IMU_data_response(sendMode, bpd_ipv6)
        print "Response Data for BPD's MAC Address is: \n\%s\'\n" % res

        # Test get latest el data:
        #res = Nm.nm_get_latest_el_data_response(sendMode, IPV6)
        #print "Latest EL EVENT  is: \n\%s\'\n" % res

    """
        #Test MAC Layer Security
        if bpd_ipv6 == BPD1_IPV6_AP:
            Nm.nm_send_CPD_cmd(sendMode, bpd_ipv6, BPD1_BRICK_MAC_ID, PAYLOAD1)
        else:
            Nm.nm_send_CPD_cmd(sendMode, bpd_ipv6, BPD1_BRICK_MAC_ID, PAYLOAD2)
    
        ret = Nm.nm_get_BPD_response(sendMode, bpd_ipv6, BPD1_BRICK_MAC_ID)
    
        print "Encoded message sent from CPD to BPD and response from BPD are: \'%s\' \n"  % str(ret)
    """

# Teardown
# Pickle the seqNum for next startup
filePath = "/tmp/picklefile.myData"
print "Updating : " + filePath + " with latest seqNum\n"

seqNum = seqNum + 1
write_data_to_file(filePath, seqNum)
#ret = Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6)