#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: Certs_Suite.py

#Suite file for Certs related testing


import unittest
from tests.TestCertsValidationHandling import *
import ResultsHandling


class Certs_Suite(unittest.TestCase):

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
        """Add"""
        result = self.a + self.b
        self.assertTrue(result == 30)

    def testsub(self):
        """Sub"""
        result = self.a - self.b
        self.assertTrue(result == -10)

def suite():
    suite = unittest.TestSuite()
    suite.addTest(TestCertsValidationHandling('test_upper'))
    suite.addTest(TestCertsValidationHandling('test_isupper'))
    suite.addTest(TestCertsValidationHandling('test_split'))
    return suite

runner = unittest.TextTestRunner()
test_suite = suite()
result = runner.run(test_suite)

#Output results statistics
from ResultsHandling import *
ResultsHandling(result)


"""
if __name__ == ' __main__':
    runner = unittest.TextTestRunner()
    test_suite = suite()
    runner.run(test_suite)
"""

#METHOD2:
#certsTestSuite.addTest(TestCertsValidationHandling('test_default_size'))
#certsTestSuite.addTest(TestCertsValidationHandling('test_resize'))


#METHOD3:
#suite = unittest.TestLoader().loadTestsFromTestCase(WidgetTestCase)

