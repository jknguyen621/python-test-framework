#!/usr/bin/python
# -*- coding: utf-8 -*-

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
    NET_MGR_PATH = pwd + '/nm'                 #'/mac_tools/net_mgr'
    NET_TRAP_PATH = pwd + '/nt'
elif platform == "linux2":                  #Raspberry Pi
    NET_MGR_PATH = pwd + '/Nm'   #''/arm_tools/net_mgr'
    NET_TRAP_PATH = pwd + '/Nt'

print "Operation System and Net_Mgr Path are: %s:%s\n" % (platform, NET_MGR_PATH)
########################################################################################################################
#NET_TRAP:
TRAP_SERVER_IPV6 = 'fd34:fe56:7891:7e23:4a8:7e53:a48e:e474'   #Local Macbook Ethernet
TRAP_LOG = "/tmp/trap_file.txt"
TRAP_PORT = "40600"
CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:004f:8917'


########################################################################################################################

CPD_MAC_ID = '00:13:50:05:00:4f:89:17'                 #Main NIC as CPD
#CPD_MAC_ID = '00:13:50:05:00:8f:de:b2'                 #Sniffer_500s station

CPD_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:004f:8917'      #CPD path via AP
#CPD_IPV6_AP = 'fe80::213:5001:0173:01c3'                   #Gen4 NIC + FSU
CPD_IPV6_FSU = 'fe80::213:5005:004f:8917'               #CPD path via FSU
#CPD_IPV6_FSU = 'fe80::213:5005:008f:deb2'              #Sniffer_500s station

CPD_IPV6_AP = CPD_IPV6_FSU

CPD_2_BPD_POLLING_INTERVAL = 30                     #In Secs, 10 secs is too short.

BPD_FW_VERSION = "14,2,1,1"
#BPD1_MAC_ID = '00:13:50:05:00:69:ce:38'               #NIC for BPD1 as temporary.
BPD1_BRICK_MAC_ID = '00:07:81:43:00:e4:e2:4d'       #'00:07:81:43:1B:AD:A5:51'
SST1 = '4954554300e4e24d'  #'495455431bada551'
CST1 = '4954526300000000'

#BPD2_MAC_ID = '00:13:50:07:00:00:0c:7e'           #NIC  for BPD2 as temporary
BPD2_BRICK_MAC_ID = '00:07:81:43:00:e4:e2:4e'                          #'00:07:81:43:1B:AD:A5:52'
SST2 = '4954554300e4e24e'        #'495455431bada552'  #Server System Title/DeviceID
CST2 = '4954526300000000'


##########################################################
#Registration Trap: nm_trap force i5s_reg 00:07:81:47:15:00:01:55 4954554315000155 04010a0c 101112131415161718192021222324
#./nm -g -d fe80::213:5005:004f:8917 nm_trap force i5s_reg [mac and dev ID/FW vers/config hash parameters required!]
REGISTRATION_TRAP = "nm_trap force i5s_reg " + BPD2_BRICK_MAC_ID + " " + SST2 + " " + "04010a0c 101112131415161718192021222324"



#NICs as temporary RF for BPD bricks
#BPD1_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5005:0069:ce38'    #BPD1 was CPD_IPV6_AP
#BPD2_IPV6_AP = 'fd04:7c3e:be2f:100f:213:5007:0000:0c7e'    #BPD2

AP_IPV6 = 'fd04:7c3e:be2f:100f:213:50ff:fe60:35b9'      #Start_word = 0x6a5d'; net_id = 0xffff

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

#COSEM_OBIS_TEST_COMMAND = "net_mgr -d IPV6 -t 20 cosem aa_sn --flags=128 xdlms --ia --cst=" + CST1 + " --sst=" + SST1 + "  --time --inv=3001 get 1:0.1.0.2.0.255:2"

OBIS_FW_VERSION = "1:0.1.0.2.0.255:2"
OBIS_UNIX_TIME = "1:0.0.1.1.0.255:2"
OBIS_SN = "1:0.0.96.1.1.255:2"
OBIS_MAC = "1:128.1.1.1.1.10:2"

DEFAULT_SECURITY_KEY = "0102030405060708090a0b0c0d0e0f10"

#DLCA Server:
DLCA_SERVER ="fde4:77d:7b24:e3cc:250:56ff:fe83:69c3"    # sjc-fwapps-01.eng.ssnsgs.net
#the below login credentials are for Jyothsna's local dlca server. you have to change it for parkcity. but password for root on parkcity:????
DLCA_USERNAME="root"
DLCA_PASSWORD="mypassword"

########################################################################################################################

#BPD Payload:
PAYLOAD1 = '08d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200'

#Get Firmware Version:
PAYLOAD2 = '09d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200'


PAYLOAD_ZERO = 'd32b0fdb005b0000000100780001004be1400030'  #can't send an empty payload, net_mgr will complain, no parameters...

PAYLOAD_FW_VER = '09d32b0fdb004d0000000100780001003de1400056ce010108495452630000000001084954554300e4e24e010c07e20a11ff0c0d0100000000000056ce0001010100010001000200ff0102000200'

PAYLOAD_1000 = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a3235000000000000100780001004be14000330400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200005b0000000100780001004be14000304001010801020304050607080103465657859834058430584954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'

PAYLOAD_1001 = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a3235000000000000100780001004be14000330400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200005b0000000100780001004be14000304001010801020304050607080103465657859834058430584954554300000000010c07e20913ff0a32350000000000003055400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'

PAYLOAD_2048 = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'

PAYLOAD_TEST = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'
PAYLOAD_MAX_VALID = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a3235000000000000100780001004be14000330400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200005b0000000100780001004be14000304001010801020304050607080103465657859834058430584954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'

SAFE_SECURED_PAYLOAD = 'd32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a3235000000000000100780001004be14000330400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200005b0000000100780001004be1400030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209'

#MAX_RAW = "980 bytes, each hex is half a byte, thus max 0-1959 text string and + 20 bytes for header or 40 text characters"
#d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be1400030400101080102030405060708010849120002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a3235000000000000100780001004be14000330400001020100010001000200ff01020002000100010001000200ff0102000200d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200005b0000000100780001004be14000304001010801020304050607080103465657859834058430584954554300000000010c07e20913ff0a323500000000000030400001020100010001000200ff01020002000100010001000200ff010200020009d32b0fdb005b0000000100780001004be140003040010108010203040506070801084954554300000000010c07e209
########################################################################################################################


########################################################################################################################
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