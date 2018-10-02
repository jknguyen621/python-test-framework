#!/usr/bin/python
# -*- coding: utf-8 -*-


#Author: Joseph K. Nguyen
#Date: September 28th, 2018
#File: reporter.py


import os
#import calendar;
from reporting.HTMLTestRunner import *
import time


def run_and_generate_Test_Report(TestSuiteName):
    pwd = os.getcwd()
    print "Current Working Direcgtory %s\n" % (pwd)

    #ts = calendar.timegm(time.gmtime())
    ts = time.strftime("%Y%m%d-%H%M%S")
    print "Current Calendar Time String is: \'%s\' \n" % (ts)


    REPORTING_PATH = pwd + '/Test_Reports/'

    outfile = open(REPORTING_PATH + "SmokeTestReport_" + ts + ".html", "wb")
    runner = HTMLTestRunner(stream = outfile,verbosity=2,title = 'JKN: Security Testing Report',description = 'MAC Layer LLS  Tests')
    runner.run(TestSuiteName)
