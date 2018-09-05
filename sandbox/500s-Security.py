#!/usr/bin/python

#Author: Joseph Nguyen 8-20-2018
#File: 500s-Security.py
#Base Python program to call and invoke net_mgr



#To execute from project's root directory: python -m sandbox.500s-Security.py    (Where package name is 'sandbox')
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

#Removing dl cert:
#print "Removing DL cert....\n"
#nm.nm_remove_cert(sendMode, CPD_IPV6_AP, '1283')


########################################################################################################################
#Upload Operator cert test:
op_x509_path = CERTS_PATH + OP_CERT
print "Uploading OP Cert...\n"
Nm.nm_upload_op_cert(sendMode, CPD_IPV6_AP, op_x509_path)

#Upload ECBOCA cert test:
ecboca_x509_path = CERTS_PATH + SUB_CA_ECBOCA_CERT
print "Uploading ECBOCA cert...\n"
Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, ecboca_x509_path)


#Upload DL cert test:
dl_x509_path = CERTS_PATH + DL_CERT
print "Uploading DL Cert...\n"
Nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)


#Upload dl cert test:
dl_x509_path = CERTS_PATH + DL_CERT
#print "Uploading DL cert...\n"
#nm.nm_upload_dl_cert(sendMode, CPD_IPV6_AP, dl_x509_path)


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
