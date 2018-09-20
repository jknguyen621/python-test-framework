#!/usr/bin/python

#Author: Joseph Nguyen 8-20-2018
#File: dut.py
#Base Python program to call and invoke net_mgr



#To execute from project's root directory: python -m sandbox.dut.py    (Where package name is 'sandbox')
from lib.nm_header import *
import lib.Nm as Nm

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



#sendMode = '-g -d'  #//via FSU
sendMode = '-d'     #via corp network & AP

########################################################################################################################

#device discovery
print "Neighbor Discovery...\n"
Nm.nm_device_discovery('-i', CPD_MAC_ID)

#Check nodeq 0
print "Check Nodeq...\n"
Nm.nm_nodeq_x('-i', '0')

#check image list on device
print "Get Image List...\n"
Nm.nm_get_image_list(sendMode, CPD_IPV6_AP)

#get version str on device
print "Get Version Str...\n"
Nm.nm_get_version_str(sendMode, CPD_IPV6_AP)


# Configure CPD to talk to BPD:
Nm.nm_configure_cpd(sendMode, CPD_IPV6_AP)
Nm.nm_configure_cpd(sendMode, BPD1_IPV6_AP)
#Nm.nm_configure_cpd(sendMode, BPD2_IPV6_AP)

# Get Random 5-digits Required ID to start communication
reqId = Nm.random_with_N_digits(5)
blobFileIn = CERTS_PATH + BLOB_FILE
privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
IPV6 = BPD1_IPV6_AP
timeOut = 30
replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
replyType2 = '03'  # HMAC, ShA256 for secured send comands

#Upload ECBOCA cert test:
ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
print "Uploading ECBOCA cert...\n"
#Nm.nm_upload_op_cert(sendMode, IPV6, ecboca_x509_path)

#Upload NMenity cert test:
dl_x509_path = CERTS_PATH + SUB_NM_CERT
print "Uploading NMenity Cert...\n"
#Nm.nm_upload_op_cert(sendMode, IPV6, dl_x509_path)

#These next 2 are done as part of DL cert generation
#Upload DLCA cert test:
dl_x509_path = CERTS_PATH + SWENG_DLCA_2019
#print "Uploading DLCA Cert...\n"
#Nm.nm_upload_dl_cert(sendMode, IPV6, dl_x509_path)

#Next would be to upload mintedDL cert....

#Check Certs Ownership level of device:
print "Validating & Checking certs ownership on devices... \'%s\'" % BPD1_IPV6_AP
Nm.nm_validate_certs_ownership(sendMode, BPD1_IPV6_AP, FULLY_DL_CHAINED_CERTS)

print "Validating & Checking certs ownership on devices... \'%s\'" % BPD2_IPV6_AP
#Nm.nm_validate_certs_ownership(sendMode, BPD2_IPV6_AP, FULLY_DL_CHAINED_CERTS)

print "Validating & Checking certs ownership on devices... \'%s\'" % CPD_IPV6_AP
Nm.nm_validate_certs_ownership(sendMode, CPD_IPV6_AP, FULLY_DL_CHAINED_CERTS)


BPD_ARRAY = [BPD1_IPV6_AP]
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
"""
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
"""

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

########################################################################################################################

if __name__ == "__main__":
    print "Running nm.py module as script"
    print "NIC info"
    sendMode = '-d'

    nm_get_image_str_version(sendMode, CPD_IPV6_AP)