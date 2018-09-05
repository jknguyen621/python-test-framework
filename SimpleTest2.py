#!/usr/bin/python
#Author: Joseph K. Nguyen
#File: SimpleTest2.py
#Dat4e: 09-05-2018


#my simple unittest tester
import unittest

def add(x,y):
    return x+y


class SimpleTest2(unittest.TestCase):
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



if __name__ == ' __main__':
    unittest.main()
