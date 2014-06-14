#!/usr/bin/env python

#= Enhanced NMAP Reporting ==================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-08
#           FH Technikum Wien
#----------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer, Hannes Trunde'

import os
import re
import sys
import time
import platform
import tempfile
import ConfigParser
from optparse import OptionParser

#----------------------------------------------------------------------------#
# check python version
if sys.version_info[0] != 2:
   print "\n\rThis script is only tested with Python 2.7\n\r"

#----------------------------------------------------------------------------#
# load config file
try:
   config = ConfigParser.ConfigParser()
   config.read("enhancedNMAPreporting.conf")
except:
    print('ERROR: Configuration File not found!')
    sys.exit(1)

#----------------------------------------------------------------------------#
# variables
verbose = False
xmlFile = ""

pre_switch = " -T4 -sP -n"
post_switch = " -vv -T4 --open --host-timeout 30m"
post_tswitch = " -sS --top-ports 3328"

#----------------------------------------------------------------------------#
# check OS
def CheckOS():
   osVar = platform.system()
   global nMAP
   global xslProc
   global mainDir
   global nsaDir
   global workDir
   global tlsPorts
   global cusCom

   tlsPorts = config.get("nmapParameter", "tlsPorts")
   cusCom = config.get("nmapParameter", "cusCom")

   if(osVar == 'Linux'):
      nMAP = config.get("externalToolsLinux", "nMAP")
      xslProc = config.get("externalToolsLinux", "xslProc")

      mainDir = config.get("PathVariablesLinux", "mainDir")
      nsaDir = config.get("PathVariablesLinux", "nsaDir")
      workDir = config.get("PathVariablesLinux", "workDir")

   elif(osVar == 'Windows'):
      nMAP = config.get("externalToolsWindows", "nMAP")
      xslProc = config.get("externalToolsWindows", "xslProc")

      mainDir = config.get("PathVariablesWindows", "mainDir")
      nsaDir = config.get("PathVariablesWindows", "nsaDir")
      workDir = config.get("PathVariablesWindows", "workDir")

   else:
      print('ERROR: Wrong OS')
      sys.exit(1)

#----------------------------------------------------------------------------#
# check function
def CheckFunction():
   checkNMAP = os.path.isfile(nMAP)
   checkXSLPROC = os.path.isfile(xslProc)
   checkMAINDIR = os.path.isdir(mainDir)
   checkNSADIR = os.path.isdir(nsaDir)
   checkWORKDIR = os.path.isdir(workDir)

   uid = os.geteuid()

   if os.geteuid() == 0:
      checkUID = True
   else:
      checkUID = False

   if(verbose):
      print('Enviroment check:\n-----------------')
      print('Check if root ............ ' + str(checkUID));
      print('Check nmap ............... ' + str(checkNMAP));
      print('Check xsltproc ........... ' + str(checkXSLPROC));
      print('Check main  Directory .... ' + str(checkMAINDIR));
      print('Check nsa Directory ...... ' + str(checkNSADIR));
      if not checkNSADIR:
         os.mkdir(nsaDir)
         checkNSADIR = os.path.isdir(nsaDir)
         print('Create nsa Directory ..... ' + str(checkNSADIR));
      print('Check Output Directory ... ' + str(checkWORKDIR));
      if not checkWORKDIR:
         os.mkdir(workDir)
         checkWORKDIR = os.path.isdir(workDir)
         print('Create work Directory .... ' + str(checkWORKDIR));
      print('-------------------------------')


   if not (checkUID and checkNMAP and checkXSLPROC and checkMAINDIR and
              checkNSADIR):
      if not (verbose):
         print('ERROR: Use -v for more Information')
      else:
         print('END')
      sys.exit(1)
   #else:
   #   print('Environment OK, start scan ...')

#----------------------------------------------------------------------------#
# get parameter
def getParameter(argv):
   parser = OptionParser("enhancedNMAPreporting.py [options] IP-Addresses")
   parser.add_option("-w", "--wan", action="store_true", dest="optWAN",
                     default=False, help="Scan over Internet")
   parser.add_option("-a", "--all", action="store_true", dest="optALL",
                     default=False, help="scan for all ports")
   parser.add_option("-s", "--ssl", action="store_true", dest="optSSL",
                     default=False, help="mix of SSL checks")
   parser.add_option("-c", "--custom", action="store_true", dest="optCUS",
                     default=False, help="Custom nmap parameter")
   parser.add_option("-v", action="store_true", dest="optVERB",
                     default=False, help="Schwafelmodus")
   parser.add_option("--ext", action="store_true", dest="optEXT",
                     default=False, help="DNS, OS and Version detection")
   parser.add_option("--PU", action="store_true", dest="optPU",
                     default=False, help="UDP host detection")
   parser.add_option("--sU", action="store_true", dest="optSU",
                     default=False, help="UDP service scan")
   parser.add_option("--ho", action="store_true", dest="optHO",
                     default=False, help="Host only detection")

   global verbose
   global args
   global pre_switch
   global post_switch
   global post_tswitch
   global hostonly
   global tlsPorts
   global cusCom

   (options, args) = parser.parse_args()
   verbose = options.optVERB
   hostonly= options.optHO

   if(options.optWAN):
      pre_switch = pre_switch + " -PE -PP --source-port 53"
      pre_switch = pre_switch + " -PS21,22,23,25,80,113,31339"
      pre_switch = pre_switch + " -PA80,113,443,10042"

   if(options.optALL):
      post_tswitch = " -sS -p-"

   if (options.optSSL):
      post_switch = post_switch + " -p" + tlsPorts

   if (options.optCUS):
      post_switch = post_switch + " " + cusCom

   if (options.optEXT):
      post_switch = post_switch + " -sV --version-all -O"
   else:
      post_switch = post_switch + " -n"

   if(options.optPU):
      pre_switch = pre_switch + " -PU"

   if(options.optSU):
      post_switch = post_switch + " -sU --top-ports 15094"

   if(len(args) < 1):
      print("Error: no IP-Address specified, use --help for more information")
      sys.exit(1)

   post_switch = post_switch + post_tswitch

#----------------------------------------------------------------------------#
# namp scan
def nmap():
   tmpFile = tempfile.NamedTemporaryFile()
   scanArea = ""
   for ip in args:
      scanArea = scanArea + " " + ip

   print("Scan for hosts at" + scanArea)
   os.system(nMAP + pre_switch + scanArea + '> ' + tmpFile.name)

   target = ""
   for ip in tmpFile:
      pattern = str(ip.split()[4:5])
      if re.search('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', pattern):
         target = target + pattern
         target = target.replace("['", "")
         target = target.replace("']", " ")

   if (hostonly):
      output = workDir + "/enr_" + time.strftime("%Y.%m.%d_%H%M") + ".txt"
      outputfile = open(output, "w")
      outputfile.write("Reachable hosts at " + scanArea + "\n")
      target = target.replace(" ", "\n")
      outputfile.write(target)
      outputfile.close()
   else:
      print("Start with fast nmap scan on discover hosts")
      xmlFile = workDir + "/enr_" + time.strftime("%Y.%m.%d_%H%M") + ".xml "
      logFile = workDir + "/enr_" + time.strftime("%Y.%m.%d_%H%M") + ".log"
      errFile = workDir + "/enr_" + time.strftime("%Y.%m.%d_%H%M") + ".err"
      os.system(nMAP + post_switch + " -oX " + xmlFile + target +
                " > " + logFile + " 2> " + errFile)

      htmlFile = workDir + "/enr_" + time.strftime("%Y.%m.%d_%H%M") + ".html"

      os.system(xslProc + " " + xmlFile + "-o " + htmlFile + " 2> " + errFile)

#----------------------------------------------------------------------------#
# main function
def main(argv):
   print('Enhanced NMAP Reporting:\n------------------------')

   t1 = time.time()
   CheckOS()
   getParameter(argv)
   CheckFunction()
   nmap()
   t2 = time.time()

   print "Time it took to call", callable, ": "
   print('Scan finished in ', t2 - t1 '\n\r')

if __name__ == "__main__":
   main(sys.argv[1:])

#============================================================================#
