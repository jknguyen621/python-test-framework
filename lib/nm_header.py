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

BPD1_MAC_ID = '00:13:50:05:00:69:ce:38'               #BPD1 was CPD
CPD_MAC_ID = '00:13:50:05:00:4f:89:17'                 #CPD
BPD2_MAC_ID = '00:13:50:07:00:00:0c:7e'               #BPD2

#CPD_IPV6_FSU = 'fe80::213:5005:0069:ce38'             #BPD1

CPD_IPV6_FSU = 'fe80::213:5005:004f:8917'               #CPD

BPD1_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:0069:ce38'    #BPD1 was CPD_IPV6_AP
CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:004f:8917'      #CPD
BPD2_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5007:0000:0c7e'    #BPD2

AP_IPV6 = 'fd04:7c3e:be2f:100f:213:50ff:fe60:35b9'      #Start_word = 0x6a5d'; net_id = 0xffff
#CERTS_PATH = '~/Certs/'                                 #Expecting ~/Certs path at the home directory for user
CERTS_PATH =  pwd+'/certs/'
OP_CERT = '01_SWENG_20224_OPERATOR.x509'
SUB_CA_ECBOCA_CERT = '02_SWENG_20224_ECBOCA_PRIV.x509'
SUB_NM_CERT = '03_SWENG_20224_NM1245.x509'
SWENG_DLCA_2019 = '02_SWENG_20224_DLCA.x509'

#DL_CERT_BPD1 = ' '                 #DL for :ce38  was DL_CERT
DL_CERT_CPD = ' '                                          #DL for
DL_CERT_BPD2 = ' '

MINTED_DL_CERT = 'dl-8d8.x509'                           #
BLOB_FILE = '03_SWENG_20224_NM1245.blob.v2blob.bin'
PRIVKEY_FILE = '03_SWENG_20224_NM1245.blob.privkey.Skey'
MFG_BLOB_FILE = ''

VALID_CHAINED_CERTS = 'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'
FULLY_DL_CHAINED_CERTS = 'Certificates owned: 0xff<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate,PrivateKeyOK>'

DAILY_BUILD_4_6_x = "//it-nas-01/release/firmware/daily-builds/4.6.x/4.6.0/4.5.0-bld5a/rni_nic/"
IMAGE ="slic_rni.nic.image.DEV.DEV_sig.04.05.995a.03"

COSEM_OBIS_TEST_COMMAND = "net_mgr -d IPV6 -t 20 cosem aa_sn --flags=128 xdlms --ia --cst=4954526300000002 --sst=0x4954554300000002 --time --inv=3001 get 1:0.1.0.2.0.255:2"

OBIS_FW_VERSION = "1:0.1.0.2.0.255:2"
OBIS_UNIX_TIME = "1:0.0.1.1.0.255:2"
OBIS_SN = "1:0.0.96.1.1.255:2"
OBIS_MAC = "1:128.1.1.1.1.10:2"

#DLCA Server:
DLCA_SERVER ="fde4:77d:7b24:e3cc:250:56ff:fe83:69c3"    # sjc-fwapps-01.eng.ssnsgs.net
#the below login credentials are for Jyothsna's local dlca server. you have to change it for parkcity. but password for root on parkcity:????
DLCA_USERNAME="root"
DLCA_PASSWORD="mypassword"

#Trap setup:
TRAP_SERVER_IPV6 = 'fd34:fe56:7891:7e23:4a8:7e53:a48e:e474'   #Local Macbook Ethernet
'''
#Set Trap server address:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap host_set fd34:fe56:7891:7e23:4a8:7e53:a48e:e474

#Set Trap listening port:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap port_set 647   #On Net Mgr on the NIC

#Set delay for trap message sent:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap delay authority_key_missing 30    #On Net Mgr on the NIC

#Service is started by: 
sudo ./net_trap -p 647  fd34:fe56:7891:7e23:4a8:7e53:a48e:e474  >> /tmp/trap_file.tx   #On local mac on 4.6 branch.

#Force a trap event example:
./net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 nm_trap force authority_key_missing   #On Net Mgr on the NIC

#Monitoring the event:
/tmp/tail -f trap_file.txt

Received *test* trap id = 0x529, seq=15, bootcnt=85, confirm=yes at time Thu Sep  6 22:32:53 2018 UTC (rx time Thu Sep  6 22:33:02 2018 UTC)
     -> reason="Authority Key Missing Test Trap" subj_key_id="da:39:a3:ee:5e:6b:4b:0d:32:55:bf:ef:95:60:18:90:af:d8:07:09" from 00:13:50:05:00:69:ce:38

'''