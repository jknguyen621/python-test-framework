#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: August 22nd, 2018
#File: Nm.py


#Purpose of this module is to house all net_mgr cmd processing.


import subprocess

NET_MGR_PATH = '/Users/jnguyen/test-framework/tools/net_mgr'
CERTS_PATH = '/Users/jnguyen/catools/catools-4.13.0b2000049/bin/'
#VALID_CHAINED_CERTS = "Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>"

VALID_CHAINED_CERTS = 'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'

#'Certificates owned: 0x7f<BirthCertificate,verifiedBC,ManufacturingCertificate,DriversLicense,verifiedDL,fullDLchain,OperatorCertificate>'
########################################################################################################################
#Command processing related:
########################################################################################################################
#Routine to handle terminal commandline processing and returning error and actual terminal output, not exit code.
def processCmd(cmd, *argv):
    for arg in argv:
        print "another arg through *argv :", arg

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
    # print cmd
    ret = processCmd(cmd)
    print ret

#Routine to get version string:
def nm_get_version_str(sendMode, IPV6):
    cmd = NET_MGR_PATH + " " + sendMode + " " + IPV6 + " get_version_str"
    # print cmd
    ret = processCmd(cmd)
    print ret

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
########################################################################################################################

if __name__ == "__main__":
    print "Running nm.py module as script"

