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
NET_MGR_PATH = '/Users/jnguyen/test-framework/tools/net_mgr'
#NET_MGR_PATH = '//home//pi//net_mgr//net_mgr'
CPD_MAC_ID = '00:13:50:05:00:69:ce:38'
CPD_IPV6_FSU = 'fe80::213:5005:0069:ce38'
CERTS_PATH = '/Users/jnguyen/catools/catools-4.13.0b2000049/bin/'
OP_CERT = '01_SWENG_20224_OPERATOR.x509'
DL_CERT = '02_SWENG_20224_DLCA.x509'
MINTED_DL_CERT = 'dl-8d8.x509'

certs_dump = NET_MGR_PATH + ' -g -d fe80::213:5005:0069:ce38 certs sdump 4'


BPD_MAC_ID = ''

sendMode = '-g -d'  #//via FSU
#sendMode = '-d'     #via corp network

#*************** COMMANDS Implemented in Nm.py module ********************#
########################################################################################################################

#discover = NET_MGR_PATH + ' -i mlme_disc_mac ' + CPD_MAC_ID

#nodeq0 = NET_MGR_PATH + ' -i nodeq 0'

#get_image_list =  NET_MGR_PATH + ' -g -d ' + CPD_IPV6_FSU + ' image list'
#get_version_str = NET_MGR_PATH + '-g -d ' + CPD_IPV6_FSU + 'get_version_str'

#dump_certs = NET_MGR_PATH + ' -g -d ' + CPD_IPV6_FSU + ' certs sdump 4'

#./net_mgr -d fd59:4c3e:1000:18:0213:5007:0000:0a44 certs upload <INSTALL_PATH>/catools-4.13.0b2000049/bin/02_SWENG_20224_DLCA.x509 c 2 persist.


########################################################################################################################

#device discovery
print "Neighbor Discovery...\n"
nm.nm_device_discovery('-i',CPD_MAC_ID)

#Check nodeq 0
print "Check Nodeq...\n"
nm.nm_nodeq_x('-i', '0')

#check image list on device
print "Get Image List...\n"
nm.nm_get_image_list(sendMode, CPD_IPV6_FSU)

#get version str on device
print "Get Version Str...\n"
nm.nm_get_version_str(sendMode, CPD_IPV6_FSU)

#Removing dl cert:
print "Removing DL cert....\n"
nm.nm_remove_cert(sendMode, CPD_IPV6_FSU, '1283')


#Upload dl cert test:
dl_x509_path = CERTS_PATH + DL_CERT
print "Uploading DL cert...\n"
#nm.nm_upload_dl_cert(sendMode, CPD_IPV6_FSU, dl_x509_path)


#Check cert chain node:
print "Check Certs chains...\n"
chain = nm.nm_cert_own(sendMode, CPD_IPV6_FSU)

#Check valid certs chain ownership:
chain.rstrip('\r\n')
ret = nm.nm_check_valid_chain(chain)
print ("Output of valid cert check = %r \n" % ret)

#Delete Operator cert and all subordinate certs:
print "Deleting Op cert and subordinates...\n"
nm.nm_certs_delete_op(sendMode, CPD_IPV6_FSU)


################################################################################
#Dump Cert Cache and returning a cert cache text table as a list
certs_list = nm.nm_dump_cert_cache(sendMode, CPD_IPV6_FSU)
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
