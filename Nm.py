#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: August 22nd, 2018
#File: Nm.py


#Purpose of this module is to house all net_mgr cmd processing.


import subprocess
import time

from random import randint

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

VALID_CHAINED_CERTS = 'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'

DAILY_BUILD_4_6_x = "//it-nas-01/release/firmware/daily-builds/4.6.x/4.6.0/4.5.0-bld5a/rni_nic/"
IMAGE ="slic_rni.nic.image.DEV.DEV_sig.04.05.995a.03"

#global seguenceNum
#sequenceNum = 0


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
    print "command terminal output: \'%s\'\n", out
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
    return ret


#Routine to get version string:
def nm_get_version_str(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " get_version_str"
    ret = processCmd(cmd)
    return ret

########################################################################################################################
#Certs related:
########################################################################################################################

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
########################################################################################################################
#Helper routines:
########################################################################################################################

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
def nm_als_secured_commands_send(sendMode,  cmdString, seqNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP, timeOut=60, replyType='03'):
    #seqNum = seqNum + 1
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + str(timeOut) + " -a " + str(replyType2) + " -A " \
          + assocId + " -k " + sharedSecret +  " -c " + str(seqNum) + " " + cmdString
    print cmd
    output = processCmd(cmd)
    print output
    seqNum += 1
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
    #global seguenceNum
    #iseguenceNum = sequenceNum + 1



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
    sequenceNum = 3
    (seqNUM,assocID, SS) = nm_als_secured_commands_send(sendMode, cmdString, sequenceNum, assocID, sharedSECRET, IPV6, timeOut,replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (seqNUM, assocID, SS)
    return (seqNUM, assocID, SS)

#Routine to return a list of current security associated ALS connections:
def nm_get_secure_association_list(sendMode, IPV6=CPD_IPV6_AP):
#Routine to teardown a specific secured ALS connection:
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " nm_sec_assoc list "
    print cmd
    out = processCmd(cmd)
    print out
    return out

def nm_teardown_ALS_connection(sendMode, seqNum, assocId, sharedSecret, IPV6=CPD_IPV6_AP):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -c " + str(0) + " nm_sec_assoc teardown "  + str(assocId) + \
          " " + sharedSecret
    print cmd
    ret = processCmd(cmd)
    print ret

########################################################################################################################

if __name__ == "__main__":
    print "Running nm.py module as script"
    print "NIC info"
    sendMode = '-d'
    #nm_get_image_str_version(sendMode, CPD_IPV6_AP)

    #Testing ALS Secured Link, reading certs cache
    #(nextSeqNum, assoc_id, sharedSecret)

    timeOut = 60
    nm_discover_thy_neighbor(sendMode, CPD_MAC_ID, 30)

    #time.sleep(10)

    #Get Random 5-digits Required ID to start communication
    reqId = random_with_N_digits(5)
    blobFileIn = CERTS_PATH + BLOB_FILE
    privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
    IPV6 = CPD_IPV6_AP
    replyType=5   #BC=0x1 + Blob=0x4 for nm_sec_assoc assoc
    replyType2='03'   #HMAC, ShA256 for secured send comands


    #Establihsing ALS connection and sendig first command via secured ALS
    (seqNum, assocId, ss) = nm_establish_ALS_connection(sendMode, IPV6=CPD_IPV6_AP,timeOut=60, reqId=12345, \
                replyType=5, replyType2='03', blobFileIn=CERTS_PATH+BLOB_FILE, privkeyFileIn=CERTS_PATH+PRIVKEY_FILE)


    #Making a second secured command request via ALS
    cmdString = " certs esdump 4 "
    (seqNum, assocId, ss) = nm_als_secured_commands_send(sendMode, cmdString, seqNum, assocId, ss, IPV6, timeOut,replyType2)
    print "Return for next command request for: seqNum;\'%d\', assocId:\'%s\', and sharedsecret:\'%s\' \n" % (
    seqNum, assocId, ss)

    #Get a list of Securit Association:
    sa_list = nm_get_secure_association_list(sendMode, IPV6)
    print "ALS ccurent Security Asscocation list is: \'%s\'\n"  % (sa_list)

    #Teardown
    ret = nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6)
