#!/usr/bin/python
#Author: Joseph K. Nguyen
#File: SimpleTest.py
#Dat4e: 09-05-2018


#my simple unittest tester
import unittest

def add(x,y):
    return x+y

class SimpleTest(unittest.TestCase):
    def test_add1(self):
        self.assertEqual(add(4,5),9)


if __name__ == ' __main__':
    unittest.main()

