#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: August 22nd, 2018
#File: Nm.py


#Purpose of this module is to house all net_mgr cmd processing.

from nm_header import *
from utilities import *
import subprocess
import time
import os

from random import randint
global seqNum


filePath = "/tmp/pickleFile.myData"

if os.path.isfile(filePath):
    seqNum = read_data_from_file(filePath)
else:
    seqNum = 0

seqNum = int(seqNum)

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
def nm_configure_cpd(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf meter_dt type 85"
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf meter_dt type"
    out = processCmd(cmd)
    print out

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf last_gasp ignore_pf_zx 3"
    processCmd(cmd)

    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " conf last_gasp ignore_pf_zx"
    out = processCmd(cmd)
    print out

########################################################################################################################
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


#Routine to sync cert, moving from P persistent to F flash memory:
def nm_cert_sync(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " certs sync "
    print cmd
    ret = processCmd(cmd)
    return ret

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
#Example: /home/pi/python-test-framework/net_mgr -d fd04:7c3e:be2f:100f:213:5005:0069:ce38 -t 60 -a 03 -A 47989 -k \
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

    global seqNum
    seqNum = seqNum + 1
    (seqNUM,assocID, SS) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocID, sharedSECRET, IPV6, timeOut,replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (seqNUM, assocID, SS)

    #Pickle the seqNum for next startup
    filePath = "/tmp/picklefile.myData"
    write_data_to_file(filePath, seqNUM)
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
    pass


#Must use App layer security association
#conf nm_sec disable_unsecure 0  #0=Open; 1=Disabled; 2=Automatio. Set to 0 for testing for emergency recovery via unsecured port.
def nm_conf_disable_unsecure(sendMode, seqNum, assocId, sharedSecret, unsecureMode, IPV6=CPD_IPV6_AP):

    cmdString = "conf nm_sec disable_unsecure " + str(unsecureMode)
    seqNum = 15   #Had to hardcode this to work around seqNum bug...
    (seqNum, assocId, ss) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP, timeOut=60,
                                  replyType='03')

    #Call again without parameters to get current set value
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
def nm_OBIS_read(sendMode, invokeID, obisCommand, IPV6=CPD_IPV6_AP):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 +  " -t 20 cosem aa_sn --flags=128 xdlms --ia \
    --cst=4954526300000002 --sst=0x4954554300000002 --time --inv=" + str(invokeID) + " get " + obisCommand
    out = processCmd(cmd)
    print out
    #return out


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

