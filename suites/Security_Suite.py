#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Security_Suite.py

#Suite file for Certs related testing


#To run this suite and prevent double invoking, from root directory type: "python -m suites.Security_Suite.py"

from unittest import TestLoader, TextTestRunner

from tests.Test_Security_TestCases import *                    #<== Import more tests.TestClasses here
from reporting.reporter import *

########################################################################################################################
#Defining Suite of Suites of Testcases. This method to handle very large set of various
# TestCases and grouping them into one major Suite.
########################################################################################################################
testList = [Test_Security]   #<== Add more TestClasses here to run collective testsuites

TestList = []
for testCase in testList:
    testSuite = unittest.TestLoader().loadTestsFromTestCase(testCase)
    TestList.append(testSuite)

newSuite = unittest.TestSuite(TestList)

run_and_generate_Test_Report(newSuite)

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