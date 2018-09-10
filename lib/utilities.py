#!/usr/bin/python

#Author: Joseph K. Nguyen
#Date: Sept 10th, 2018
#File: utilities.py

#This file will store mainly file ios, processing, etc... , independent of test logic.


import os
import cPickle as pickle


########################################################################################################################
#Routine to archive/pickle data

def write_data_to_file(filePath, myData):
    with open(filePath, 'w') as pickle_handle:
        pickle.dump(myData, pickle_handle)


def read_data_from_file(filePath):
    with open(filePath) as pickle_handle:
        result = pickle.load(pickle_handle)
        return result