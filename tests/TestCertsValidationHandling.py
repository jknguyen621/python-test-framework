#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: TestCertsValidationHandling.py


#This is the first of the series of UnitTest implemented as a trial run on Python to test and validation errors handling of various Certs operations.



from lib.nm_header import *
import lib.Nm as Nm

import unittest


class TestCertsValidationHandling(unittest.TestCase):


    #Setup required to run our testcase/suite.

    def setUp(self):
        #self.certsTest = Widget('The widget')
        sendMode = '-d'

        timeOut = 60
        #Nm.nm_discover_thy_neighbor(sendMode, CPD_MAC_ID, 30)

        reqId = Nm.random_with_N_digits(5)
        blobFileIn = CERTS_PATH + BLOB_FILE
        privkeyFileIn = CERTS_PATH + PRIVKEY_FILE
        IPV6 = CPD_IPV6_AP
        replyType = 5  # BC=0x1 + Blob=0x4 for nm.nm_sec_assoc assoc
        replyType2 = '03'  # HMAC, ShA256 for secured send comands

        # Configure CPD to talk to BPD:
        Nm.nm_configure_cpd(sendMode, IPV6)

        # Establihsing ALS connection and sendig first command via secured ALS
        (seqNum, assocId, ss) = Nm.nm_establish_ALS_connection(sendMode, IPV6, timeOut=60, reqId=12345,
                                                               replyType=5, replyType2='03',
                                                               blobFileIn=CERTS_PATH + BLOB_FILE,
                                                               privkeyFileIn=CERTS_PATH + PRIVKEY_FILE)
        self.assertTrue(self, (assocId !=0 or ss != ''), "Wrong response for ")



    #Tear down setup ready for next test run.
    def tearDown(self):
        #self.assertTrue(Nm.nm_teardown_ALS_connection(sendMode, seqNum, assocId, ss, IPV6, "Ok", 'Failed to Disconnect'))
        pass


    if __name__ == '__main__':            # unittest.main()


