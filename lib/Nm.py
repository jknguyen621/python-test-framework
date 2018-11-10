#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Joseph K. Nguyen
#Date: August 22nd, 2018
#File: Nm.py


#Purpose of this module is to house all net_mgr cmd processing.

from nm_header import *
from utilities import *
import subprocess
import time
import os
import sys

from random import randint
#from pygtail import Pygtail
global seqNum


filePath = "/tmp/pickleFile.myData"

if os.path.isfile(filePath):
    seqNum = read_data_from_file(filePath)
else:
    seqNum = 0

print "INITIAL SEQNUM IS: \'%d\'\n"  % (seqNum)
seqNum = int(seqNum)
SEQ_NUM = seqNum


IPV6 = ""
sendMode = ""
#NOTE: Set which BPD_DUT is running on this particular test bed.
BPD_DUT = BPD1_BRICK_MAC_ID
#BPD_DUT = BPD2_BRICK_MAC_ID


#Selecting CPD with BPD based on testing
if BPD_DUT == BPD1_BRICK_MAC_ID:   #Xroot Certd CPD&BPD combo with access to BOS.
    CPD_DUT = CPD1_IPV6_AP         #BPD1 will be using AP, with DLCA, and X/Rooot
    IPV6 = CPD_DUT
    sendMode = "-d "
else:
    CPD_DUT = CPD2_IPV6_FSU        #Local, using FSU
    IPV6 =  CPD_DUT
    sendMode = "-g -d "



#'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'
########################################################################################################################
#Command processing related:
########################################################################################################################
#Routine to handle terminal commandline processing and returning error and actual terminal output, not exit code.
def processCmd(cmd, *argv):
    for arg in argv:
        print "another arg through *argv :", arg

    print ("Processing Command: \'%s\' \n" % cmd)
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    #print "command terminal output: \'%s\' \n" % str(out)
    return out

#Command to restart the device(meter, AP, whatever with an IPV6)
def nm_restart_now(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " restart now "
    print ("Processing Command: \'%s\' \n" % cmd)
    ret = processCmd(cmd)
    print "Wait for the device to reboot, be back in 30 sec...\n"
    time.sleep(30)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " image list"
    print ("Processing Command: \'%s\' \n" % cmd)
    ret = processCmd(cmd)
    print ret

########################################################################################################################
#Discovery and Nodeq checking related:
########################################################################################################################
#Routine to discover nearby neighbor by Mac ID:
def nm_device_discovery(sendMode, device_mac_id):
    cmd = NET_MGR_PATH + " " + sendMode + " " +  "mlme_disc_mac " + device_mac_id
    #print cmd
    ret = processCmd(cmd)
    print ret


#Routine to return various nodeq check
#Refer to this wiki for all the nodeq IDs: https://zoo.silverspringnet.com/display/PlatformFW/Nodeq
def nm_nodeq_x(sendMode, nodeId):
    cmd = NET_MGR_PATH + " " + sendMode + " " + "nodeq " + str(nodeId)
    print cmd
    out = processCmd(cmd)
    print out
    return out

########################################################################################################################
#Image and Version related:
########################################################################################################################

#Routine to check device image list:
def nm_get_image_list(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 +  " image list"
    ret = processCmd(cmd)
    print ret
    return ret


#Routine to get version string:
def nm_get_version_str(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " get_version_str"
    ret = processCmd(cmd)
    print ret
    return ret


########################################################################################################################
#Configurations related:
########################################################################################################################

#Configure CPD to talk to BPD:
# conf meter_dt type 85
# last_gasp ignore_pf_zx 3
# Need to use 4.6 image and latest net_mgr
# Refer to this wiki: https://zoo.silverspringnet.com/pages/viewpage.action?spaceKey=FwEng&title=500INS+CPD+Configuration
def nm_configure_cpd(sendMode, IPV6, BPD=BPD2_BRICK_MAC_ID):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf meter_dt type 85"
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf meter_dt type"
    out = processCmd(cmd)
    print out

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf last_gasp ignore_pf_zx 3"
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf last_gasp ignore_pf_zx"
    processCmd(cmd)

    #Next 2 commands to enable USB Serial debug for lack of LLS MAC
    """
    conf i5s enable	1	Initialize 500INS proxy application. //Requires a reboot
    conf i5s dbs	0	Connect to BPD NCL via OTA
    Note - compile option allows directing COSEM messages directly to debug serial for initial development.
    """

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf lls enable 1"  # Enable lls
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf lls enable"  # Check again on lls
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf imu_proxy imu_mm_enable 0"  # Disabling imu mm
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf imu_proxy imu_mm_enable"  # Check again on disabling imu mm
    processCmd(cmd)


    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s enable 1"   #When changing values, need to reboot.
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s enable"  # Check Value.
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s dbs 0"    #0 - OTA; 1 - Serial for DBS
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s dbs"      #Check value 0 - OTA; 1 - Serial for DBS
    processCmd(cmd)

    #Note: For BPD's ecurity to be enabled, we need to set: conf i5s linksec 0 and in the setup_ins.cs script: /* Save To Flash */
    #DBI("07 58 01");  #00 - clear text, disable security.

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s linksec 0"  # Set link security to normal security 0,  3 for clear text
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf i5s linksec"  # Check value of i5s linksec
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf lls_bls interval " + str(CPD_2_BPD_POLLING_INTERVAL)  # Minimimum interval in seconds between BPD's response to request.
    processCmd(cmd)

    #No longer needed after BPD build 14.1.1.20
    #cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " app_sysvar 1246:0x00:0x07:0x81:0x43"                   #BPD's 4 bytes prefix for usbserial mode.
    #out = processCmd(cmd)

    #Really need a reboot here to make these values persist.
    #nm_restart_now(sendMode, IPV6)

    #Inject default security key between CPD and BPD
    print "Loading default secured key for BPD on CPD...\n"
    nm_inject_security_key(sendMode, IPV6, BPD, DEFAULT_SECURITY_KEY, 1)
    #NOTE: Will get Errorneous request error for now, since there is a bug in the deteltion of the key FIRMW-19441

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " evstatus [108, 109, 110, 111, 126, 361,362]:on" #Turn on events:  KIO_PKT_SEND (361), KIO_PKT_RECV (362)
    processCmd(cmd)


    #Temp Set Registration Trap:
    #REGISTRATION_TRAP = "nm_trap force i5s_reg " + BPD2_BRICK_MAC_ID + " " + SST2 + "04010a0c 101112131415161718192021222324"
    print "Setting temporary i5s_reg trap...\n"
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + REGISTRATION_TRAP
    processCmd(cmd)

    #Show Mac security key on CPD for BPD:
    print "Verifying that secured key was loaded successfully....\n"
    nm_show_mac_sec_key(sendMode, IPV6, BPD, 1)

def test_create_or_register_40_Devices(self):
    #"nm_trap force i5s_reg " + BPD2_BRICK_MAC_ID + " " + SST2 + " " + "04010a0c 101112131415161718192021222324"
    TEST_SST = "4954554300e4e2"
    TEST_BPD ="00:07:81:43:00:e4:e2:"
    for i in range(1, 42):  #Will go to 41, expect OK, but node 41 will not be registered, not even Node #40, since its my real BPD itself.
        i = '{num:02d}'.format(num=i)
        print "Registering CPD device #:%s\n" % str(i)
        cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + "nm_trap force i5s_reg " + TEST_BPD+str(i) + " " + TEST_SST+str(i) + " " + "04010a0c 101112131415161718192021222324"
        ret = processCmd(cmd)
        print ret
        time.sleep(5)


#Check LLS enabled:
def nm_check_lls_enabled(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " lls_nodeq show all"
    out = processCmd(cmd)
    print out
    return out

#Display nlog show dev:
def nm_nlog_show_dev(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nlog show dev"
    out = processCmd(cmd)
    print out
    return out

#Clear nlog:
def nm_nlog_clear_dev(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nlog clear dev"
    out = processCmd(cmd)
    print out
    return out

#Display events:
def nm_event(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " event"
    out = processCmd(cmd)
    print out
    return out

#Clear event log:
def nm_event_clear(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " event clear"
    out = processCmd(cmd)
    print out
    return out

#Clear all logs:
def nm_clear_logs(sendMode, IPV6):
    print "Clearing nlog dev...\n"
    nm_nlog_clear_dev(sendMode, IPV6)

    print "Clearing the event log...\n"
    nm_event_clear(sendMode, IPV6)
    time.sleep(1)

#########################################################################################################################
#Certs related:
########################################################################################################################

# INDEX values are: (2)birth, (3)Mfg, (4)Cert Cache,
#         (5)Ecck1 pub key, (6)Ecck2 pub key, (7)Ecck3 pub key, (8)Ecck4 pub key,
#         GIDs are a class: (0)General, (1)Op Certs (2)DL Certs.
#


#Routine to show the various types of certs based on Index value
def nm_show_cert(sendMode, IPV6, index):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs show " + str(index)
    # print cmd
    certs = processCmd(cmd)
    return certs

#Routine to dump the cert cache:
def nm_dump_cert_cache(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs esdump 4"
    # print cmd
    certs = processCmd(cmd)
    return certs


#Routine to upload Operator Cert to persistent memory:
def nm_upload_op_cert(sendMode, IPV6, path2x509):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs upload " + path2x509 + " persist"
    print cmd
    ret = processCmd(cmd)
    print ret


#Routine to upload DL to persistent memory:
def nm_upload_dl_cert(sendMode, IPV6, path2x509):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs upload " + path2x509 + " c 2 persist"
    print cmd
    ret = processCmd(cmd)
    print ret


#Routine to upload Manufacturing blob:
def nm_upload_mfg_blob(sendMode, IPV6, path2BlobFile):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs upload_blob" + path2BlobFile
    print cmd
    ret = processCmd(cmd)
    print ret


#Routine to download Certs, to local working directory:
#**Where, INDEX values are: (2)birth, (3)Mfg, (4)Cert Cache,
#         (5)Ecck1 pub key, (6)Ecck2 pub key, (7)Ecck3 pub key, (8)Ecck4 pub key,
#         GIDs are a class: (0)General, (1)Op Certs (2)DL Certs.
#i.e: #Operator Cert downlaod: ./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 certs dload OPERATOR 4 c 1
def nm_download_cert(sendMode, IPV6, baseName, indexValue, gidClassl):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs dload " + baseName + " " + str(indexValue) + " c "  + str(gidClass)
    print cmd
    ret = processCmd(cmd)
    print ret

#Routine to remove cert
def nm_remove_cert(sendMode, IPV6, privateID):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs erase " + privateID
    print cmd
    ret = processCmd(cmd)
    print ret


#Routine to check cert chain node:
def nm_cert_own(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs own "
    print cmd
    ret = processCmd(cmd)
    #print ret
    return ret


#Routine to delete Operator Cert and  all subordinate certs from the Cache
def nm_certs_delete_op(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs delete_op "
    print cmd
    ret = processCmd(cmd)
    print ret

def nm_delete_sysvar(sendMode, IPV6, ID): #360 for certs cache  app_sysvar delete:360
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " app_sysvar delete:" + ID
    print cmd
    ret = processCmd(cmd)
    time.sleep(10)
    print ret

#Routine to sync cert, moving from P persistent to F flash memory:
def nm_cert_sync(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs sync "
    print cmd
    ret = processCmd(cmd)
    return ret

#Routine to validate Certs ownership of a device
def nm_validate_certs_ownership(sendMode, IPV6, expectedCertsOwnershipLevel):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs own "
    print cmd
    ret = processCmd(cmd)
    print ret
    if ret.rstrip() == expectedCertsOwnershipLevel:
        print "PASSED: Got expected Level of Certs Ownership for device: \'%s\' : \'%s\'\n" % (IPV6, ret)
        return "PASSED"
    else:
        print "FAILED: Certs Ownership level for device is not at proper level: \'%s\'\n" % ret
        return "FAILED"

#######################################################################################################################
#Insert security key between CPD & BPD
#ie.: DEFAULT_SECURITY_KEY
def nm_inject_security_key(sendMode, IPV6, bpdMacId, sec_key, index=1):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " mac_secmib add  " + str(bpdMacId) + " " + str(index) + " " + str(sec_key)
    print cmd
    ret = processCmd(cmd)
    print "inject key rc =:\'%s\'\n" % (ret)
    return ret


#TO view secuirty key on the CPD for BPD
def nm_show_mac_sec_key(sendMode, IPV6, bpdMacId, index=1):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " mac_secmib show  " + str(bpdMacId) + " " + str(index)
    print cmd
    ret = processCmd(cmd)
    print "Security key on CPD for BPD at index \'%d\' is: \'%s\' \n"  % (index, str(ret))
    print ret
    return ret

#Get Current transfer Frame Counter for the BPD Node
def nm_get_TxFrameCounter(sendMode, IPV6, bpdMacId, index=1):
    rc = nm_show_mac_sec_key(sendMode, IPV6, bpdMacId, index=1)
    print rc
    lines = rc.split('\n')
    #for line in lines:
        #print "line: %s \n" % (line)
        #pass
    TxFrameCount = lines[3].split(':')[-1]
    return TxFrameCount.lstrip()

#######################################################################################################################
#IMU or Master Meter Reading related, read imu Data and el events
########################################################################################################################
#Get range of imu data
def nm_imu_data_range(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " imu_data range"
    print cmd

    range  = processCmd(cmd)
    list = range.split('\n')

    item1 = list[0]
    item2 = list[1]

    max = item1.split(' ')[-2]
    min = item2.split(' ')[-2]
    return (min, max)

#read specific Imu data by index
def nm_imu_data_read_index(sendMode, IPV6, index):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " imu_data read " + index
    print cmd
    readData = []
    readData = processCmd(cmd)
    return readData

#read imu data read_last
def nm_imu_data_read_last(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " imu_data read_last " + index
    print cmd
    readData = []
    readData = processCmd(cmd)
    return readData

#Get range of el data
def nm_el_data_range(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " el_data range"
    print cmd

    range  = processCmd(cmd)
    print range
    list = range.split('\n')

    item1 = list[0]
    item2 = list[1]

    max = item1.split(' ')[-1]
    min = item2.split(' ')[-1]
    #print min, max
    return (min, max)


#read specific el data by index
def nm_el_data_read_index(sendMode, IPV6, index):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " el_data read " + index
    print cmd
    readData = []
    readData = processCmd(cmd)
    return readData

#######################################################################################################################
#Helper routines:
########################################################################################################################

#Routine to get the last data range and retrieve its data.
#Meant to be used with OBIS requests or any kind of IMU Data requests
def nm_get_latest_IMU_data_response(sendMode, IPV6):
    (min, max) = nm_imu_data_range(sendMode, IPV6)
    #print "Max:Min: \'%s\':\'%s\' \n" % (max, min)

    responseData = nm_imu_data_read_index(sendMode, IPV6, max)
    return responseData


#Routine to get the last el data range and retrieve its data.
def nm_get_latest_el_data_response(sendMode, IPV6):
    (min, max) = nm_el_data_range(sendMode, IPV6)
    print "Max:Min: \'%s\':\'%s\' \n" % (max, min)

    responseData = nm_el_data_read_index(sendMode, IPV6, max)
    return responseData


#Routine to loop and get neihbor on nodeq 0, useful after a reboot.
def nm_discover_thy_neighbor(sendMode, device_macId, timeOut=60):

    sendMode = '-i '
    linkedDevice = ''
    loopCount = 1
    while linkedDevice == 'None' or linkedDevice =='':
        nm_device_discovery(sendMode, device_macId)
        nodeId = 0
        linkedDevice = nm_nodeq_x(sendMode, nodeId)
        print "Trying connection loop: \'%d\' \n" % loopCount
        loopCount += 1
        time.sleep(1)

    print "Linked Device list is: \'%s\' \n"  % linkedDevice


#Random required ID:
#Usage:  print random_with_N_digits(5)
def random_with_N_digits(n):
    range_start = 10 ** (n - 1)
    range_end = (10 ** n) - 1
    return randint(range_start, range_end)

#Routine to check for valid certs ownership:
def nm_check_valid_chain(actualCertsOwned, expectedCertsOwned=VALID_CHAINED_CERTS):
    actualCertsOwned.rstrip('\r')
    if (str(actualCertsOwned) == str(expectedCertsOwned)):
        return True
    else:
        print "actual: \'%s\'" % str(actualCertsOwned)
        print "expected: \'%s\'" % str(expectedCertsOwned)
        return False


#Routine to run by default when run module as test script
def nm_get_image_str_version(sendMode, IPV6):

    nm_get_image_list(sendMode, IPV6)
    nm_get_version_str(sendMode, IPV6)


#Get assoc ID from nm_sec_assoc assoc response
def nm_get_assocId_from_assoc_response(outputString):
    out = []
    out = outputString.split('\n')

    import re
    assocID = re.findall(r'\d+', out[2])
    return assocID[0]

#Get Shared Secret from nm_sec_assoc assoc response
def nm_get_shared_secret_from_assoc_response(outputString):
    out = []
    out = outputString.split('\n')
    return out[10]

#Routine for secured commands send via ALS:
#Example: /home/pi/python-test-f ret = processCmd(cmd)ramework/net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -t 60 -a 03 -A 47989 -k \
# ecdd06e7fc092a4ad054d569d35d25ed25ac51d422e8f074c1528f718ffa88e5 -c 1 image list
#NOTE:  "-a Sign message with specified sig
    # 1st digit - sig type:
    #     0: HMAC, 1: RSA, 2: ECDSA, 3: DSA
    # 2nd digit - HMAC hash type:
    #     0: No sig, 1: SHA1, 2: SHA224, 3: SHA256, 4: SHA384, 5: SHA512
    # For non-HMAC sigs, the 2nd digit has to be '0'
    # Note: The only valid argument is '03'"
def nm_als_secured_commands_send(sendMode,  cmdString, sequenceNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP, timeOut=60, replyType='03'):
    #seqNum = seqNum + 1
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + str(timeOut) + " -a " + str(replyType) + " -A " \
          + assocId + " -k " + sharedSecret +  " -c " + str(sequenceNum) + " " + cmdString
    print cmd
    output = processCmd(cmd)
    print output
    global seqNum
    seqNum = sequenceNum + 1

    return(seqNum, assocId, sharedSecret)

#Routine to configure security associate ALS:
#Example: /home/pi/python-test-framework/net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -t 60 -c 0 nm_sec_assoc assoc_conf \
# 3600 0 0 47989 ecdd06e7fc092a4ad054d569d35d25ed25ac51d422e8f074c1528f718ffa88e5

def nm_sec_assoc_conf(sendMode, assocId, sharedSecret, IPV6=CPD_IPV6_AP, encryptType=0, hmacType=0, timeOut=60,idle_timeOut=3000):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + str(timeOut) + " -c 0 " + "nm_sec_assoc assoc_conf " \
          + str(idle_timeOut) + " " + str(encryptType) + " " + str(hmacType) + " " + str(assocId) + " " + sharedSecret
    print cmd
    (output) = processCmd(cmd)
    print output
    #return (seqNum, assocId, sharedSecret)

#Routine to security associate ALS:
#note: replyType = reply_type: 0x1=BC, 0x2=MFC, 0x4=blob (7=all)  (OR-ed)
#Example: /home/pi/python-test-framework/net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -t 60 -c 0 nm_sec_assoc assoc \
# 12345 5 /home/pi/Certs/03_SWENG_20224_NM1245.blob.v2blob.bin  /home/pi/Certs/03_SWENG_20224_NM1245.blob.privkey.Skey

def nm_sec_assoc_assoc(sendMode, replyType, blobFileIn=CERTS_PATH+BLOB_FILE, privkeyFileIn=CERTS_PATH+PRIVKEY_FILE,
                                                                                                IPV6=CPD_IPV6_AP,timeOut=60, reqId=12345):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + str(timeOut) + " -c 0 " + "nm_sec_assoc assoc " \
          + str(reqId) + " " + str(replyType) + " " + blobFileIn + " " + privkeyFileIn

    output = processCmd(cmd)
    print output

    assocId = nm_get_assocId_from_assoc_response(output)

    print ("Returned process ASSOC_ID = \'%s\' " % assocId)
    # return (seqNum, assocId, sharedSecret)

    sharedS = nm_get_shared_secret_from_assoc_response(output)
    print ("Returned process Shared Secret = \'%s\' " % sharedS)

    return (assocId, sharedS)

#Main upper level Routine to help establish Application Layer Security &
#For secured Application command processing.  Will call lower-level routines for configuration and connection.
#returns:  the next seqNum to use for command, assoc_id, shared secret
#Required: blob bin and privkey files for the particular operator in the ~/Certs directory.
#Example: /home/pi/python-test-framework/net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -t 60 -c 0 nm_sec_assoc assoc \
# 12345 5 /home/pi/Certs/03_SWENG_20224_NM1245.blob.v2blob.bin  /home/pi/Certs/03_SWENG_20224_NM1245.blob.privkey.Skey
#reply_type: 0x1=BC, 0x2=MFC, 0x4=blob (7=all)
def nm_establish_ALS_connection(sendMode, IPV6=CPD_IPV6_AP, timeOut=60,reqId=12345, replyType=5, replyType2='03', \
                                blobFileIn=CERTS_PATH+BLOB_FILE, privkeyFileIn=CERTS_PATH+PRIVKEY_FILE):


    #1): Call nm_sec_assoc_assoc ().... Get initial assocID and SharedSecret
    (assocID, sharedSECRET) = nm_sec_assoc_assoc(sendMode, replyType, blobFileIn, privkeyFileIn,IPV6, timeOut, reqId)


    #2): Calling nm_sec_assoc_conf() ALS tunnel configuration parameters.
    nm_sec_assoc_conf(sendMode, assocID, sharedSECRET, IPV6, 0, 0, timeOut, 3000)

    #3):  Send net_mgr commands string via secured ALS tunnel.
    cmdString = "image list"

    global SEQ_NUM
    seqNum = SEQ_NUM
    print "Current Global seqNum inside nm_establish_ALS is: \'%d\' \n" % (seqNum)
    seqNum = seqNum + 1
    (seqNUM,assocID, SS) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocID, sharedSECRET, IPV6, timeOut,replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (seqNUM, assocID, SS)

    #Pickle the seqNum for next startup
    filePath = "/tmp/picklefile.myData"
    write_data_to_file(filePath, seqNUM)
    SEQ_NUM = seqNum
    return (seqNUM, assocID, SS)

#Routine to return a list of current security associated ALS connections:
def nm_get_secure_association_list(sendMode, IPV6=CPD_IPV6_AP):
#Routine to teardown a specific secured ALS connection:
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nm_sec_assoc list "
    print cmd
    out = processCmd(cmd)
    print out
    return out

#Routine to teardown existing ALS link.  Note there is a bug with using actual seqNum, workaround using null port: FIRMW-19357
def nm_teardown_ALS_connection(sendMode, seqNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -c " + str(0) + " nm_sec_assoc teardown "  + str(assocId) + \
          " " + sharedSecret
    print cmd
    ret = processCmd(cmd)
    print ret

#########################################################################################################################
#Security level and backdoor unsecure(legacy port) disabling methods.

#Routine to set security level
#0x0 - None
#0x7 -  Compatibility Mode
#0xF - Strict
def nm_conf_mlme_sec_level():
    cmdString = "conf mlme sec_level " + str(level)
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + cmdString
    # print cmd
    ret = processCmd(cmd)
    print ret

#Must use App layer security association
#conf nm_sec disable_unsecure 0  #0=Open; 1=Disabled; 2=Automatio. Set to 0 for testing for emergency recovery via unsecured port.
def nm_conf_disable_unsecure(sendMode, seqNum, assocId, sharedSecret, unsecureMode, IPV6=CPD_IPV6_AP):

    cmdString = "conf nm_sec disable_unsecure " + str(unsecureMode)
    #seqNum = 15   #Had to hardcode this to work around seqNum bug...

    (seqNum, assocId, ss) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP, timeOut=60,
                                  replyType='03')

    #Call again without parameters to get current set value, READ-ONLY
    cmdString = "conf nm_sec disable_unsecure "
    (seqNUM, assocID, SS) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6=CPD_IPV6_AP, timeOut=60,
                                 replyType='03')
    return (seqNUM, assocID, SS)

#Set Link Layer Security Idle limit timeout,   Default is set to 2 days.  Set to 1 day for testing.
def nm_conf_set_link_layer_idle_limit(sendMode, noOfDay, IPV6=CPD_IPV6_AP):
    cmdString = " conf nm_sec link_layer_sec_idle_limit" + " " + str(noOfDay)
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + cmdString
    # print cmd
    ret = processCmd(cmd)

    #Call again to see set status
    cmdString = " conf nm_sec link_layer_sec_idle_limit"
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + cmdString
    # print cmd
    ret = processCmd(cmd)
    print ret


#Set Applicaiton Layer Security Association idle limit timeout.  Default is set for 4 days.  Set to 1 day for testing.
def nm_conf_set_app_layer_idle_limit(sendMode, noOfDay, IPV6=CPD_IPV6_AP):
    cmdString = " conf nm_sec auto_lpo_idle_limit" + " " + str(noOfDay)
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + cmdString
    # print cmd
    ret = processCmd(cmd)

    # Call again to see set status
    cmdString = " conf nm_sec auto_lpo_idle_limit"
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + cmdString
    # print cmd
    ret = processCmd(cmd)
    print ret

########################################################################################################################
#OBIS Commands using COSEM from onboard NIC to BPD

#Routine to send OBIS command to BPD via NIC using IPV6
def nm_OBIS_read(sendMode, invokeID, obisCommand, bpd_id, IPV6=CPD_IPV6_AP):

    cmd = ''

    if (bpd_id == BPD1_BRICK_MAC_ID):
        cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 +  " -t 20 cosem aa_sn --flags=128 xdlms --ia --cst=" + CST1 + " --sst=" + SST1 + " --time --inv=" + str(invokeID) + " get " + obisCommand
    elif (bpd_id == BPD2_BRICK_MAC_ID):
        cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t 20 cosem aa_sn --flags=128 xdlms --ia --cst=" + CST2 + " --sst=" + SST2 + " --time --inv=" + str(invokeID) + " get " + obisCommand
    else:
        pass
    out = processCmd(cmd)
    print out
    #return out


########################################################################################################################
#CPD to BPD commands:

#Define routine to send raw payload command to BPD via CPD:
#net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -v lls_nodeq cmd 00:07:81:43:00:BC:61:4E
def nm_send_CPD_cmd(sendMode, IPV6, bpdMac, payload):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t 20 -v lls_nodeq cmd " + bpdMac + " " + payload
    out = processCmd(cmd)
    print out
    return out

#Routine to display response from BPD to CPD and encoded message sent.
#net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -v lls_nodeq show all
def nm_show_BPD_LLS_Nodes(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t 20 -v lls_nodeq show all "
    out = processCmd(cmd)
    print out
    return out

#Routine to send secured payload
def nm_send_secured_CPD_cmd(sendMode, IPV6, bpdMac, payload, secMode, index=1):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t 20 -v lls_nodeq cmd " + bpdMac + " " + payload + " " + str(secMode) + " " +  str(index)
    out = processCmd(cmd)
    print out
    return out



#Routine to mimic 3 retries of reading after each BLS timeframe
def nm_retries(sendMode, IPV6):
    # Sleep a little longer to ensure we get the expected event in the event log.
    print "Sleep a little longer to ensure robustness of respond messages..."
    time.sleep(60)

    # Get event log for APP layer secure events:
    rc = Nm.nm_event(sendMode, IPV6)
    print rc

    self.assertTrue('sec_level=6' and 'LLS_RX_SDU' in rc,
                    "Did not get proper security level in the event log 'sec_level=6' as expected")
########################################################################################################################
#Trap Server I setup locally on mac:
"""#Set Trap server address:
    ./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap host_set fd34:fe56:7891:7e23:4a8:7e53:a48e:e474
    
    #Set Trap listening port:
    ./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap port_set 647   #On Net Mgr on the NIC
    
    #Set delay for trap message sent:
    ./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap delay authority_key_missing 0    #On Net Mgr on the NIC
    
    #Service is started by: 
    sudo ./net_trap -p 647  fd34:fe56:7891:7e23:4a8:7e53:a48e:e474  >> /tmp/trap_file.tx   #On local mac on 4.6 branch.
    
    #Force a trap event example:
    ./net_mgr -d fd04:7c3e:be2f:100f:213:5005:004f:8917 nm_trap force authority_key_missing   #On Net Mgr on the NIC
    
    #Monitoring the event:
    /tmp/tail -f trap_file.txt
    
    Received *test* trap id = 0x529, seq=15, bootcnt=85, confirm=yes at time Thu Sep  6 22:32:53 2018 UTC (rx time Thu Sep  6 22:33:02 2018 UTC)
         -> reason="Authority Key Missing Test Trap" subj_key_id="da:39:a3:ee:5e:6b:4b:0d:32:55:bf:ef:95:60:18:90:af:d8:07:09" from 00:13:50:05:00:69:ce:38
"""
#en3: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	# options=10b<RXCSUM,TXCSUM,VLAN_HWTAGGING,AV>
	# ether a8:60:b6:2f:d8:6c
	# inet6 fe80::1033:67b8:87c7:f57e%en3 prefixlen 64 secured scopeid 0xe
	# inet6 fd34:fe56:7891:7e23:4a8:7e53:a48e:e474 prefixlen 64 autoconf secured  <= This one (SSNI wifi)

def nm_config_trap_server(sendMode, IPV6, localServerIPV6):
    #Set host name
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nm_trap host_set " + localServerIPV6
    out = processCmd(cmd)
    print out

    #Set host port
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nm_trap port_set " + TRAP_PORT  #647
    out = processCmd(cmd)
    print out

    # Set delay for authority_key_missing
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nm_trap delay authority_key_missing 0"
    out = processCmd(cmd)
    print out

    # start trap server  (NOTE: More reliable to start manually outside of the framework!!!)
    #sudo ./net_trap -p 40600  fd34:fe56:7891:7e23:4a8:7e53:a48e:e474  >> /tmp/trap_file.tx   #On local mac on 4.6 branch.
    #cmd = "sudo " +NET_TRAP_PATH + " -p " + TRAP_PORT + " " + localServerIPV6 + " >> " + TRAP_LOG + " &"
    #out = processCmd(cmd)
    #print out

    #print "Please excute this cmd in a new terminal:\n"
    #print "sudo ./nt -p 40600 fd34:fe56:7891:7e23:4a8:7e53:a48e:e474 >> /tmp/trap_file.txt"
    time.sleep(10)

def nm_force_trap_event(trap, sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + "nm_trap force  " + str(trap)
    ret = processCmd(cmd)
    return ret


def nm_tail_file(filePath, expectedValue=None):

    expetedValue1 = "Received "
    """
    if expectedValue == None:
        dummyRead = Pygtail(filePath, read_from_end=True)

    for line in Pygtail(filePath,  read_from_end=True, paranoid=True):
        sys.stdout.write(line)
        if expetedValue1 in line:
            myList = line.split('=')
            print myList
            myList2 = myList[1].split(',')
            actualValue = myList2[0].lstrip()
            print "Hex Value Received is: \'%s\' \n" % actualValue
            return actualValue
        else:
            pass
    """
    pass


def nm_config_ndxp_dlca_server(sendMode, IPV6, ndxp_server):
    #net_mgr -g -d fe80::213:5005:008f:deb2 conf nm_sec ndxp_server fde4:77d:7b24:e3cc:250:56ff:fe83:46ec
    #SWENG_QA_NDXP = 'fde4:77d:7b24:e3cc:250:56ff:fe83:46ec'
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + "conf nm_sec ndxp_server  " + ndxp_server
    ret = processCmd(cmd)
    return ret

def nm_get_app_nodeq(sendMode, IPV6):
    # ./nm -g -d fe80::213:5005:004f:8917 i5s_app_nodeq show
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " " + "-v i5s_app_nodeq show"
    ret = processCmd(cmd)
    return ret

########################################################################################################################

if __name__ == "__main__":
    print "Running nm.py module as script"
    print "NIC info"
    sendMode = '-d'

    nm_get_image_str_version(sendMode, CPD_IPV6_AP)

    #Testing ALS Secured Link, reading certs cache
    #(nextSeqNum, assoc_id, sharedSecret)

    timeOut = 60
    nm_discover_thy_neighbor(sendMode, CPD_MAC_ID, 30)

