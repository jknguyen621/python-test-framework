#!/usr/bin/python
#Author: Joseph Nguyen 8-20-2018
#File: 500s-Security.py
#Base Python program to call and invoke net_mgr


import time 
import sys
import os
import string
import Nm as nm

LOOP_MAX = 1

NET_MGR_PATH = ''
from sys import platform
if platform == "darwin" or platform == "linux":
    NET_MGR_PATH = '/Users/jnguyen/PycharmProjects/python-test-framework/net_mgr'
elif platform == "linux2":                  #Raspberry Pi
    NET_MGR_PATH = '/home/pi/python-test-framework/arm_net_mgr/net_mgr'

print "Operation System and Net_Mgr Path are: %s:%s\n" % (platform, NET_MGR_PATH)



CPD_MAC_ID = '00:13:50:05:00:69:ce:38'
CPD_IPV6_FSU = 'fe80::213:5005:0069:ce38'
CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:0069:ce38'
AP_IPV6 = 'fd04:7c3e:be2f:100f:213:50ff:fe60:35b9'      #Start_word = 0x6a5d'; net_id = 0xffff
CERTS_PATH = '~/Certs/'                                 #Expecting ~/Certs path at the home directory for user
OP_CERT = '01_SWENG_20224_OPERATOR.x509'
SUB_CA_ECBOCA_CERT = '02_SWENG_20224_ECBOCA_PRIV.x509'
DL_CERT = '03_SWENG_20224_NM1245.x509'
MINTED_DL_CERT = 'dl-8d8.x509'
BLOB_FILE = '03_SWENG_20224_NM1245.blob.v2blob.bin'
PRIVKEY_FILE = '03_SWENG_20224_NM1245.blob.privkey.Skey'

certs_dump = NET_MGR_PATH + ' -g -d fe80::213:5005:0069:ce38 certs sdump 4'


BPD_MAC_ID = ''

#sendMode = '-g -d'  #//via FSU
sendMode = '-d'     #via corp network & AP

########################################################################################################################

#device discovery
print "Neighbor Discovery...\n"
nm.nm_device_discovery('-i',CPD_MAC_ID)

#Check nodeq 0
print "Check Nodeq...\n"
nm.nm_nodeq_x('-i', '0')

#check image list on device
print "Get Image List...\n"
nm.nm_get_image_list(sendMode, CPD_IPV6_AP)

#get version str on device
print "Get Version Str...\n"
nm.nm_get_version_str(sendMode, CPD_IPV6_AP)

#Removing dl cert:
#print "Removing DL cert....\n"
#nm.nm_remove_cert(sendMode, CPD_IPV6_AP, '1283')

#Upload Operator cert test:
op_x509_path = CERTS_PATH + OP_CERT
print "Uploading OP Cert...\n"
nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, op_x509_path)

#Upload ECBOCA cert test:
ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
print "Uploading ECBOCA cert...\n"
nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, ecboca_x509_path)


#Upload DL cert test:
dl_x509_path = CERTS_PATH + DL_CERT
print "Uploading DL Cert...\n"
nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)


#Upload dl cert test:
dl_x509_path = CERTS_PATH + DL_CERT
#print "Uploading DL cert...\n"
#nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)


#Check cert chain node:
print "Check Certs chains...\n"
chain = nm.nm_cert_own(sendMode, CPD_IPV6_AP)

#Check valid certs chain ownership:
chain.rstrip('\r\n')
ret = nm.nm_check_valid_chain(chain)
print ("Output of valid cert check = %r \n" % ret)

#Delete Operator cert and all subordinate certs:
print "Deleting Op cert and subordinates...\n"
nm.nm_certs_delete_op(sendMode, CPD_IPV6_AP)


################################################################################
#Dump Cert Cache and returning a cert cache text table as a list
certs_list = nm.nm_dump_cert_cache(sendMode, CPD_IPV6_AP)
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
