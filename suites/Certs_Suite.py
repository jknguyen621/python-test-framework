#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Certs_Suite.py

#Suite file for Certs related testing


#To run this suite and prevent double invoking, from root directory type: "python -m suites.Certs_Suite.py"

from unittest import TestLoader, TextTestRunner, suite, defaultTestLoader
from tests.Test_Dut import *                    #Import more tests.TestClasses here
import ResultsHandling as rh

########################################################################################################################
#Defining Suite of Suites of Testcases. This method to handle very large set of various
# TestCases and grouping them into one major Suite.
########################################################################################################################
testList = [Test_Dut]   #Add more TestClasses here to run collective testsuites

TestList = []
for testCase in testList:
    testSuite = unittest.TestLoader().loadTestsFromTestCase(testCase)
    TestList.append(testSuite)

newSuite = unittest.TestSuite(TestList)
result = unittest.TextTestRunner(verbosity=2).run(newSuite)

#Output results statistics
rh.ResultsHandling(result)


########################################################################################################################
#For smaller subset suite to test, one can use this 2nd way to declare and run suite:
########################################################################################################################
# def suite():
#     suite = unittest.TestSuite()
#     suite.addTest(Test_Dut('test01_cosem_obis_get_fw_version'))
#     suite.addTest(Test_Dut('test02_send_raw_payload_to_BPD'))
#     suite.addTest(Test_Dut('test03_send_various_size_payloads_to_BPD'))
#     return suite
#
# suite = suite()
# result = unittest.TextTestRunner(verbosity=2).run(suite)
########################################################################################################################
########################################################################################################################
if __name__ == '__main__':
    unittest.main()