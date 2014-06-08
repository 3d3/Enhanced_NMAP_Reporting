#!/usr/bin/env python

#= Enhanced NMAP Reporting ==================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-08
#           FH Technikum Wien
#----------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer'

import os
import sys
import ConfigParser

#----------------------------------------------------------------------------#
# load config file
config = ConfigParser.ConfigParser()
config.read("./enhancedNMAPreporting.conf")

#----------------------------------------------------------------------------#
# variables
nMAP = config.get("externalTools", "nMAP")
xslProc = config.get("externalTools", "xslProc")

tempDir = config.get("PathVariables", "tempDir")
workDir = config.get("PathVariables", "workDir")

verbose = True

#----------------------------------------------------------------------------#
# check function

def CheckFunction():
   checkNMAP = os.path.isfile(nMAP)
   checkXSLPROC = os.path.isfile(xslProc)
   checkTEMPDIR = os.path.isdir(tempDir)
   checkWORKDIR = os.path.isdir(workDir)

   if(verbose):
      print('Enviroment check:\n-----------------')
      print('Check nmap ............. ' + str(checkNMAP));
      print('Check xsltproc ......... ' + str(checkXSLPROC));
      print('Check temp Directory ... ' + str(checkTEMPDIR));
      print('Check work Directory ... ' + str(checkWORKDIR) + '\n');

   if not (checkNMAP and checkXSLPROC and checkTEMPDIR and checkWORKDIR):
      if not (verbose):
         print('ERROR: Use -v for more Information')
      exit()
   else:
      print('Environment OK, start scan ...')

#----------------------------------------------------------------------------#
# main function

print('Enhanced NMAP Reporting:\n------------------------\n')

CheckFunction()




#----------------------------------------------------------------------------#
#if __name__ == "__main__":

#============================================================================#
