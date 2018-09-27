#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Certs_Suite.py

#Suite file for Certs related testing


import unittest
from unittest import suite
#from tests.TestCertsValidationHandling import *
from tests.Test_Dut import *
import ResultsHandling
from lib.nm_header import *

IPV6 = CPD_IPV6_AP

class Certs_Suite(unittest.TestCase):

    """
    def setUp(self):
        self.a = 10
        self.b =  20
        name = self.shortDescription()

        if name == "add":
            self.a =  10
            self.b =  20
            print name, self.a, self.b

        if name == "sub":
            self.a =  50
            self.b = 60
            print name, self.a, self.b

    def tearDown(self):
         print "\nend of test", self.shortDescription()

    def testadd(self):
        '''Add'''
        result = self.a + self.b
        self.assertTrue(result == 30)

    def testsub(self):
        '''Sub'''
        result = self.a - self.b
        self.assertTrue(result == -10)
    """

#def suite():
    #suite = unittest.TestSuite()
    #suite.addTest(TestCertsValidationHandling('test_upper'))
    #suite.addTest(TestCertsValidationHandling('test_isupper'))
    #suite.addTest(TestCertsValidationHandling('test_split'))



class TestLoaderWithKwargs(unittest.TestLoader):
    """A test loader which allows to parse keyword arguments to the
       test case class."""

    def loadTestsFromTestCase(self, testCaseClass, **kwargs):
        """Return a suite of all tests cases contained in
           testCaseClass."""
        if issubclass(testCaseClass, suite.TestSuite):
            raise TypeError("Test cases should not be derived from " \
                            "TestSuite. Maybe you meant to derive from" \
                            " TestCase?")
        testCaseNames = self.getTestCaseNames(testCaseClass)
        if not testCaseNames and hasattr(testCaseClass, 'runTest'):
            testCaseNames = ['runTest']

        # Modification here: parse keyword arguments to testCaseClass.
        test_cases = []
        for test_case_name in testCaseNames:
            test_cases.append(testCaseClass(test_case_name, **kwargs))
        loaded_suite = self.suiteClass(test_cases)

        return loaded_suite

#runner = unittest.TextTestRunner()
#test_suite = suite()
#result = runner.run(test_suite)

# call your test
loader = TestLoaderWithKwargs()
suite = loader.loadTestsFromTestCase(Test_Dut)
result = unittest.TextTestRunner(verbosity=2).run(suite)

#Output results statistics
from ResultsHandling import *
ResultsHandling(result)

#if __name__ == '__main__':
#    unittest.main()


"""
if __name__ == ' __main__':
    runner = unittest.TextTestRunner()
    test_suite = suite()
    runner.run(test_suite)
"""

