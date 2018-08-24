#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: August 22nd, 2018
#File: Nm.py


#Purpose of this module is to house all net_mgr cmd processing.


import subprocess

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

VALID_CHAINED_CERTS = 'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'

#'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'
########################################################################################################################
#Command processing related:
########################################################################################################################
#Routine to handle terminal commandline processing and returning error and actual terminal output, not exit code.
def processCmd(cmd, *argv):
    for arg in argv:
        print "another arg through *argv :", arg

    print ("Processing Command: %s\n" % cmd)
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    print "command terminal output: ", out
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
    cmd = NET_MGR_PATH + " " + sendMode + " " + "nodeq " + nodeId
    print cmd
    ret = processCmd(cmd)
    print ret

########################################################################################################################
#Image and Version related:
########################################################################################################################

#Routine to check device image list:
def nm_get_image_list(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 +  " image list"
    #print cmd
    ret = processCmd(cmd)
    print ret
    return ret

#Routine to get version string:
def nm_get_version_str(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " get_version_str"
    # print cmd
    ret = processCmd(cmd)
    print ret
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
    #print ret
    return ret
########################################################################################################################
#Helper routines:
########################################################################################################################

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

    ret = nm_get_image_list(sendMode, IPV6)
    print ret

    ret = nm_get_version_str(sendMode, IPV6)
    return ret

#Routein for secured commands via ALS:
def nm_als_secured_commands_send(sendMode, IPV6=CPD_IPV6_AP, timeOut=60, replyType, cmdString, seqNum, assocId, sharedSecret):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + timeOut + " -A " + replyType + " -k " + sharedSecret +  -c " + seqNum + " " +cmdString
    print cmd
    (out, err) = processCmd(cmd)
    print out


#Routine to configure security associate ALS:
def nm_sec_assoc_conf(sendMode, IPV6=CPD_IPV6_AP,timeOut=60, idle_timeOut=3000, encryptType, hmacType, assocId, sharedSecret):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " -t " + timeOut + " -c 0 " + "nm_sec_assoc assoc_conf " \
          + idle_timeOut + " " + encryptType + " " + hmacType + " " + assocId + " " + sharedSecret
    print cmd
    (out, err) = processCmd(cmd)
    print out
    return (seqNum, assocId, sharedSecret)


#Routine to security associate ALS:
def nm_sec_assoc_assoc(sendMode, IPV6=CPD_IPV6_AP,reqId, blobFileIn=CERTS_PATH+BLOB_FILE, privkeyFileIn=CERTS_PATH+PRIVKEY_FILE):



#Routine to help establish Application Layer Security &
#return the next seqNum to use for command, assoc_id, shared secret
#For secured Application command processing
def nm_Establish_ALS_Connection(sendMode, IPV6=CPD_IPV6_AP,reqId=12345, blobFileIn=CERTS_PATH+BLOB_FILE, privkeyFileIn=CERTS_PATH+PRIVKEY_FILE):

    #/home/pi/Certs/03_SWENG_20224_NM1245.blob.v2blob.bin
    #/home/pi/Certs/03_SWENG_20224_NM1245.blob.privkey.Skey



    #1): Request to establish ALS security association via IPV6 address provided.
    #

    #2): ALS tunnel configuration parameters.
    #nm_sec_assoc_conf(sendMode, IPV6=CPD_IPV6_AP,timeOut=60, idle_timeOut=3000, encryptType, hmacType, assocId, sharedSecret):

    #3):  Send net_mgr commands string via secured ALS tunnel.
    #nm_als_secured_commands_send(sendMode, IPV6=CPD_IPV6_AP, timeOut=60, replyType, cmdString, seqNum, assocId,
                                 sharedSecret):
########################################################################################################################

if __name__ == "__main__":
    print "Running nm.py module as script"
    print "NIC info"
    sendMode = '-d'
    nm_get_image_str_version(sendMode, CPD_IPV6_AP)

