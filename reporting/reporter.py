#!/usr/bin/python
# -*- coding: utf-8 -*-


#Author: Joseph K. Nguyen
#Date: September 28th, 2018
#File: reporter.py


import os
import calendar;
from reporting.HTMLTestRunner import *


def run_and_generate_Test_Report(TestSuiteName):
    pwd = os.getcwd()
    print "Current Working Direcgtory %s\n" % (pwd)

    ts = calendar.timegm(time.gmtime())
    print "Current Calendar-TimeStamp is: \'%d\' \n" % (ts)

    REPORTING_PATH = pwd + '/Test_Reports/'

    outfile = open(REPORTING_PATH + "SmokeTestReport_" + str(ts) + "_.html", "wb")
    runner = HTMLTestRunner(stream = outfile,verbosity=2,title = 'JKN: Security Testing Report',description = 'MAC Layer LLS  Tests')
    runner.run(TestSuiteName)
