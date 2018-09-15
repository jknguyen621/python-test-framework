#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Nm_Tester.py

from lib.nm_header import *
from lib.utilities import *
import lib.Nm as Nm
import os

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

# time.sleep(10)

# Get Random 5-digits Required ID to start communication
reqId = Nm.random_with_N_digits(5)
blobFileIn = CERTS_PATH + BLOB_FILE
privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
IPV6 = CPD_IPV6_AP
replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
replyType2 = '03'  # HMAC, ShA256 for secured send comands

# Configure CPD to talk to BPD:
Nm.nm_configure_cpd(sendMode, IPV6)

# Establihsing ALS connection and sendig first command via secured ALS
(seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, IPV6, timeOut=60, reqId=12345, \
                                                       replyType=5, replyType2='03', blobFileIn=CERTS_PATH + BLOB_FILE, privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)

# Making a second secured command request via ALS
cmdString = " certs esdump 4 "
(seqNum, assocId, ss) = Nm.nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,
                                                        replyType2)
print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
    seqNum, assocId, ss)

# Get a list of Securit Association:
# sa_list = nm.nm_get_secure_association_list(sendMode, IPV6)
# print "ALS ccurent Security Asscocation list is: \'%s\'\n"  % (sa_list)


# Disable unsecured port for safety net during testing as a way to recover.
# NOTE: if you use net_mgrS for connection, it will enable the unsecured port on Gen5 NIC.
unsecureMode = 0  # DISABLED


seqNum = seqNum + 11  #For some resason, when we start to disable unsecured port, seqNum increased by 11
(seqNum, assocId, ss) = Nm.nm_conf_disable_unsecure(sendMode, seqNum, assocId, ss, unsecureMode, IPV6)

# Set Link Layer Idle Timeout to 1 day:
noOfDay = 1
Nm.nm_conf_set_link_layer_idle_limit(sendMode, noOfDay, IPV6)

#Set IPV6 = BPD under test:
IPV6 = BPD1_IPV6_AP
#IPV6 = BPD2_IPV6_AP

# Set App Layer idle timeout to 1 day:
Nm.nm_conf_set_app_layer_idle_limit(sendMode, noOfDay, IPV6)

# show various types of certs:
Nm.nm_show_cert(sendMode, IPV6, 2)  # Birth

Nm.nm_show_cert(sendMode, IPV6, 3)  # MFG

# nm.nm_show_cert(sendMode, IPV6, 4) #Cert Cache


obisInvokeID = 11111

# Read BPD's FW Version
obisCommand = OBIS_FW_VERSION
print "READING BPD FW VERSION\n"
Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, IPV6)
obisInvokeID += 1

# Get resonse:
res = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
print "Response Data for BPD's FW Version is: \n\%s\'\n" % res

# Read BPD's Unix Time
obisCommand = OBIS_UNIX_TIME
print "READING BPD TIME\n"
Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, IPV6)
obisInvokeID += 1

# Get resonse:
res = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
print "Response Data for BPD's Unix Time is: \n\%s\'\n" % res

# Read BPD's SN
obisCommand = OBIS_SN
print "READING BPD S/N\n"
Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, IPV6)
obisInvokeID += 1

# Get resonse:
res = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
print "Response Data for BPD's SN is: \n\%s\'\n" % res

# Read BPD's MAC ID
obisCommand = OBIS_MAC
print "READING BPD MAC ID\n"
Nm.nm_OBIS_read(sendMode, obisInvokeID, obisCommand, IPV6)
obisInvokeID += 1

# Get resonse:
res = Nm.nm_get_latest_IMU_data_response(sendMode, IPV6)
print "Response Data for BPD's MAC Address is: \n\%s\'\n" % res

# Test get latest el data:
#res = Nm.nm_get_latest_el_data_response(sendMode, IPV6)
#print "Latest EL EVENT  is: \n\%s\'\n" % res

# Teardown
# Pickle the seqNum for next startup
filePath = "/tmp/picklefile.myData"
print "Updating : " + filePath + " with latest seqNum\n"

seqNum = seqNum + 1
write_data_to_file(filePath, seqNum)
#ret = Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6)