# python-test-framework
Sandbox for Python framework for smart meter test automation


1. To Run Test_Dut.py:
  python -m sandbox.Test_Dut.py  
  
  
2. To Run Nm_Tester.py:
  python Nm_Tester.py
  
3. To Run Tests under ./tests directory:
  python -m unittest tests.TestName (w/o the .py)
  
4. To Run Suites under ./suites directory:
  python -m unittest suites.SuiteName (w/o the .py)
  
5. To Run trapTester.py:
  python -m miscellaneous.trapTester.py
  
  
6.  ./lib/500sanity.zip is to be unzipped onto a windows environment and run with COSEM DevBench.
7.  ./arm_net_mgr are tools for Raspberry Pi OS.
 
 
Fundamentally,  to start, you should create tests in the sandbox, lets call it Test_XYZ.py.
Once you are satisfied with it, you can copy it to ./tests directory.
Add the Test class in the Test Suite under ./suites directory and call the test by name such as:

from tests.Test_Dut import *

 
suite.addTest(Test_Dut('test_cosem_obis_get_fw_version')) 
 
