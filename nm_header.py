#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: nm_header.py


#This is the commmon header file for this framework, should be imported as * to consumers, i.e.: from nm_header import *
#All Global shared parameters, configurations and constants should be declared in this file.




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
MFG_BLOB_FILE = ''

VALID_CHAINED_CERTS = 'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'

DAILY_BUILD_4_6_x = "//it-nas-01/release/firmware/daily-builds/4.6.x/4.6.0/4.5.0-bld5a/rni_nic/"
IMAGE ="slic_rni.nic.image.DEV.DEV_sig.04.05.995a.03"

COSEM_OBIS_TEST_COMMAND = "net_mgr -d IPV6 -t 20 cosem aa_sn --flags=128 xdlms --ia --cst=4954526300000002 --sst=0x4954554300000002 --time --inv=3001 get 1:0.1.0.2.0.255:2"

OBIS_FW_VERSION = "1:0.1.0.2.0.255:2"
OBIS_UNIX_TIME = "1:0.0.1.1.0.255:2"
OBIS_SN = "1:0.0.96.1.1.255:2"
OBIS_MAC = "1:128.1.1.1.1.10:2"