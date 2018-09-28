#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: September 28th, 2018
#File: reporter.py


import os
import calendar;
import time;
from HTMLTestRunner import *

def run_and_generate_Test_Report(TestSuiteName):
    pwd = os.getcwd()
    print "Current Working Direcgtory %s\n" % (pwd)

    ts = calendar.timegm(time.gmtime())
    print(ts)

    REPORTING_PATH = pwd + '/Test_Reports/'

    outfile = open(REPORTING_PATH + "SmokeTestReport_" + str(ts) + "_.html", "w")
    runner = HTMLTestRunner(stream = outfile,title = 'Security Test Report',description = 'Certs Sanity Tests')
    runner.run(TestSuiteName)
    #return runner

""" 
title = saxutils.escape(self.title),
generator = generator,
stylesheet = stylesheet,
heading = heading,
report = report,
ending = ending,
"""