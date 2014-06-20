#!/usr/bin/env python

#= Enhanced NMAP Reporting ================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-08
#           FH Technikum Wien
#--------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer, Hannes Trunde'

import os
import sys
import time
import urllib
import platform
import tempfile
import ConfigParser
from optparse import OptionParser

#--------------------------------------------------------------------------#
# check python version
if sys.version_info[0] != 2:
   print "\n\rThis script is only tested with Python 2.7\n\r"

#--------------------------------------------------------------------------#
# load config file
try:
   config = ConfigParser.ConfigParser()
   config.read("enhancedNMAPreporting.conf")
except:
    print('ERROR: Configuration File not found!')
    sys.exit(1)

#--------------------------------------------------------------------------#
# variables
verbose = False
xmlFile = ""

pre_switch = " -T4 -sP -n"
post_switch = " -vv -T4 --open --host-timeout 30m"
post_tswitch = " -sS --top-ports 3328"

#--------------------------------------------------------------------------#
# check OS
def CheckOS():
   osVar = platform.system()
   global nMAP
   global xslProc
   global xml2csv
   global mainDir
   global nseDir
   global workDir
   global tlsPorts
   global cusCom

   tlsPorts = config.get("nmapParameter", "tlsPorts")
   cusCom = config.get("nmapParameter", "cusCom")

   if(osVar == 'Linux'):
      nMAP = config.get("externalToolsLinux", "nMAP")
      xslProc = config.get("externalToolsLinux", "xslProc")
      xml2csv = config.get("externalToolsLinux", "xml2csv")

      mainDir = config.get("PathVariablesLinux", "mainDir")
      nseDir = config.get("PathVariablesLinux", "nseDir")
      workDir = config.get("PathVariablesLinux", "workDir")

   elif(osVar == 'Windows'):
      nMAP = config.get("externalToolsWindows", "nMAP")
      xslProc = config.get("externalToolsWindows", "xslProc")

      mainDir = config.get("PathVariablesWindows", "mainDir")
      nseDir = config.get("PathVariablesWindows", "nseDir")
      workDir = config.get("PathVariablesWindows", "workDir")

   else:
      print('ERROR: Wrong OS')
      sys.exit(1)

#--------------------------------------------------------------------------#
# check function
def CheckFunction():
   global checkXSLPROC
   global checkXML2CSV

   checkNMAP = os.path.isfile(nMAP)
   checkXSLPROC = os.path.isfile(xslProc)
   checkXML2CSV = os.path.isfile(xml2csv)

   checkMAINDIR = os.path.isdir(mainDir)
   checkNSEDIR = os.path.isdir(nseDir)
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
      print('Check xml_to_csv.py....... ' + str(checkXML2CSV));
      print('Check main  Directory .... ' + str(checkMAINDIR));
      print('Check nse Directory ...... ' + str(checkNSEDIR));
      if not checkNSEDIR:
         os.mkdir(nseDir)
         checkNSEDIR = os.path.isdir(nseDir)
         print('Create nse Directory ..... ' + str(checkNSEDIR));
      print('Check Output Directory ... ' + str(checkWORKDIR));
      if not checkWORKDIR:
         os.mkdir(workDir)
         checkWORKDIR = os.path.isdir(workDir)
         print('Create work Directory .... ' + str(checkWORKDIR));
      print('Check nse Scripts ........ ' + str(nseCheck()));
      print('-------------------------------')

   if not (checkUID and checkNMAP and checkMAINDIR and checkNSEDIR):
      if not (verbose):
         print('ERROR: Use -v for more Information')
      else:
         print('END')
      sys.exit(1)

#--------------------------------------------------------------------------#
# get parameter
def getParameter(argv):
   parser = OptionParser("enhancedNMAPreporting.py [options] IP-Addresses")
   parser.add_option("-w", "--wan", action="store_true", dest="optWAN",
                     default=False, help="Scan over Internet")
   parser.add_option("-a", "--all", action="store_true", dest="optALL",
                     default=False, help="scan for all ports")
   parser.add_option("-s", "--ssl", action="store_true", dest="optSSL",
                     default=False, help="mix of SSL checks")
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
   parser.add_option("--customcommand", action="store_true",
                     dest="optCusCom", default=False,
                     help="Custom nmap parameter")
   parser.add_option("--customport", action="store_true",
                     dest="optCusPrt",default=False,
                     help="Custom Ports to scan")

   global verbose
   global args
   global pre_switch
   global post_switch
   global post_tswitch
   global hostonly
   global tlsPorts

   global optCusCom
   global optCusPrt

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
      post_switch = post_switch + " --script " + nseDir  + " -d -p" +\
                    tlsPorts

   if (options.optCusCom):
      post_switch = post_switch + " " + cusCom

   if (options.optCusPrt):
      post_switch = post_switch + " -p " + optCusPrt

   if (options.optEXT):
      post_switch = post_switch + " -sV --version-all -O"

   if(options.optPU):
      pre_switch = pre_switch + " -PU"

   if(options.optSU):
      post_switch = post_switch + " -sU --top-ports 15094"

   if not options.optEXT or not options.optSSL:
      post_switch = post_switch + " -n"

   if not options.optCusPrt or not options.optSSL:
      post_switch = post_switch + post_tswitch

   if(len(args) < 1):
      print("Error: no IP-Address specified, use --help "
            "for more information")
      sys.exit(1)

#--------------------------------------------------------------------------#
# nmap nse scripts
def nseCheck():
   getconf = True
   returnCode = True
   conf = 0
   try:
      url = config.get("nmapSSLnseScripts", "url")
   except:
      print('ERROR: No NSE-URL declared')
      returnCode = False

   while getconf:
      conf += 1
      scriptNumber = "script." + str(conf)
      try:
         script = config.get("nmapSSLnseScripts", scriptNumber)
         scirptPath = nseDir + "/" + script
         if not (os.path.isfile(scirptPath)):
            print('Download NSE Script....... ' + str(script));
            uri = url + script
            urllib.urlretrieve (uri, scirptPath)
      except:
         getconf = False

   return returnCode

#--------------------------------------------------------------------------#
# namp scan
def nmap():
   output = workDir + "/enr_" + time.strftime("%Y%m%d_%H%M") + ".txt"
   xmlFile = workDir + "/enr_" + time.strftime("%Y%m%d_%H%M") + ".xml "
   logFile = workDir + "/enr_" + time.strftime("%Y%m%d_%H%M") + ".log"
   errFile = workDir + "/enr_" + time.strftime("%Y%m%d_%H%M") + ".err"
   htmlFile = workDir + "/enr_" + time.strftime("%Y%m%d_%H%M") + ".html"

   tmpFile = tempfile.NamedTemporaryFile()
   scanArea = ""
   for ip in args:
      scanArea = scanArea + " " + ip

   print("Scan for hosts at" + scanArea)
   os.system(nMAP + pre_switch + scanArea + '> ' + tmpFile.name +
             " 2> " + errFile)

   target = ""
   targetArea = tmpFile.read().split()
   for item in targetArea:
      if len( item.split(".") ) == 4:
         item = item.replace("(", "")
         item = item.replace(")", "")
         target = target + " " + item

   if (hostonly):
      outputfile = open(output, "w")
      outputfile.write("Reachable hosts at " + scanArea + "\n")
      target = target.replace(" ", "\n")
      outputfile.write(str(target))
      outputfile.close()
   else:
      print("Start with fast nmap scan on discover hosts ...")
      os.system("cd /opt/enr/nse && " + nMAP + post_switch + " -oX " +
                xmlFile + target + " > " + logFile + " 2> " + errFile)

      if(checkXSLPROC):
         print("Build html File ...")
         os.system(xslProc + " " + xmlFile + "-o " + htmlFile + " 2> " +
                   errFile)

      if checkXML2CSV:
         print("Start to convert xml to csv ...")
         os.system(xml2csv + " " + xmlFile)

#--------------------------------------------------------------------------#
# main function
def main(argv):
   print('Enhanced NMAP Reporting:\n------------------------')

   CheckOS()
   getParameter(argv)
   CheckFunction()
   nmap()

   print('Scan finished.')

if __name__ == "__main__":
   main(sys.argv[1:])

#==========================================================================#
