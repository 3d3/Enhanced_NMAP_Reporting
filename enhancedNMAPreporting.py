#!/usr/bin/env python

#= Enhanced NMAP Reporting ==================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-08
#           FH Technikum Wien
#----------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer, Hannes Trunde'

import os
import sys
import platform
import ConfigParser

#----------------------------------------------------------------------------#
# load config file
config = ConfigParser.ConfigParser()
config.read("./enhancedNMAPreporting.conf")

#----------------------------------------------------------------------------#
# variables

verbose = True

pre_switch = "-T4 -sP -n"
post_switch = "-vv -T4 --open --host-timeout 30m -iL ${tempFile}"
post_switch = "${post_switch} -oN ${OUTPUT}.txt -oX ${OUTPUT}.xml"
post_switch = "${post_switch} -oG ${OUTPUT}_go.txt"
post_tswitch = "-sS --top-ports 3328"

#----------------------------------------------------------------------------#
# check OS

def CheckOS():
   osVar = platform.system()
   global nMAP
   global xslProc
   global tempDir
   global workDir

   if(osVar == 'Linux'):
      nMAP = config.get("externalToolsLinux", "nMAP")
      xslProc = config.get("externalToolsLinux", "xslProc")

      tempDir = config.get("PathVariablesLinux", "tempDir")
      workDir = config.get("PathVariablesLinux", "workDir")
   elif(osVar == 'Windows'):
      nMAP = config.get("externalToolsWindows", "nMAP")
      xslProc = config.get("externalToolsWindows", "xslProc")

      tempDir = config.get("PathVariablesWindows", "tempDir")
      workDir = config.get("PathVariablesWindows", "workDir")
   else:
      print('ERROR: Wrong OS')
      exit()

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

CheckOS()
CheckFunction()



#----------------------------------------------------------------------------#
#if __name__ == "__main__":

#============================================================================#
