# python-test-framework

#Author: Joseph K. Nguyen
#Date: August 20th, 2018
#File: README.md


Sandbox for Python framework for smart meter test automation


1. To Run Test_Dut.py:
  python -m sandbox.Test_Dut.py  
  
  
2. To Run Nm_Tester.py:
  python Nm_Tester.py
  
3. To Run Tests under ./tests directory:
  python -m unittest tests.TestName (w/o the .py)
  
4. To Run Suites under ./suites directory:
  python -m unittest suites.SuiteName (w/o the .py)  #This will run things twice.
  Solution: python -m suites.Security_Suite.py   (w/o the unittest and with the *.py)
  
5. To run individual test within a TestCase (helps in quickly developing tests):
    #python -m unittest testMyCase.MyCase.testItIsHot
    i.e.: I want to run only this test for debugging: test10_test_send_secure_mode_cosem_obis_cmd
    python -m unittest tests.Test_Security_TestCases.Test_Security.test10_test_send_secure_mode_cosem_obis_cmd
    
6. To Run trapTester.py:
  python -m miscellaneous.trapTester.py
  
7.  ./lib/500sanity.zip is to be unzipped onto a windows environment and run with COSEM DevBench.
8.  ./arm_net_mgr are tools for Raspberry Pi OS.
 
 
Fundamentally,  to start, you should create tests in the sandbox, lets call it Test_XYZ.py.
Once you are satisfied with it, you can copy it to ./tests directory.
Add the Test class in the Test Suite under ./suites directory and call the test by name such as:

from tests.Test_Dut import *

 
suite.addTest(Test_Dut('test_cosem_obis_get_fw_version')) 

Suggestions:
-----------
1. To create a symbolic link on your environment like so:
ln -s /Users/jnguyen/python-test-framework/mac_tools/net_mgr /Users/jnguyen/python-test-framework/nm
 - then call your net_mgr like so: ./nm -d fd04:7c3e:be2f:100f:213:5005:004f:8917 image list

2. Similarly, on Pi, it would be:
ln -s /home/pi/python-test-framework/arm_tools/net_mgr /home/pi/python-test-framework/Nm
- then call your net_mgr like so: ./Nm -d fd04:7c3e:be2f:100f:213:5005:004f:8917 image list

=========================================================================================
External Dependencies:
  
  
  NOTE: 
  COSEM/OBIS commands are issued at the Application level.
  lls_nodeq cmd 00:07:81:43:1B:AD:A5:52 <PAYLOAD> [SecMode] [Index] is at the Link Layer level
  
  Use '#TODO' sparingly for identified temporary hacks or upcoming features that are not ready yet.
  
  
  
 
 
