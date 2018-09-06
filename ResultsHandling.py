#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 5th, 2018
#File: ResultsHandling.py

#Handles Result outputting

import unittest

class ResultsHandling(unittest.TestResult):
    def __init__(self, result):
        print "--- START OF TEST RESULTS"
        print result

        print "result:errors"
        print result.errors

        print "result:failures"
        print result.failures

        print "result::skipped"
        print result.skipped

        print "result:successful"
        print result.wasSuccessful()

        print "result::test-run"
        print result.testsRun
        print "---END OF TEST RESULTS\n"
