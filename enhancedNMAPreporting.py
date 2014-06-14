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
import tempfile
import subprocess
import ConfigParser
from optparse import OptionParser

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

pre_switch = " -T4 -sP -n"
post_switch = " -vv -T4 --open --host-timeout 30m -iL ${tempFile}"
post_switch = post_switch + " -oX ${OUTPUT}.xml"
post_tswitch = "-sS --top-ports 3328"

#----------------------------------------------------------------------------#
# check OS
def CheckOS():
   osVar = platform.system()
   global nMAP
   global xslProc
   global mainDir
   global nsaDir
   global workDir
   global tempDir


   if(osVar == 'Linux'):
      nMAP = config.get("externalToolsLinux", "nMAP")
      xslProc = config.get("externalToolsLinux", "xslProc")

      mainDir = config.get("PathVariablesLinux", "mainDir")
      nsaDir = config.get("PathVariablesLinux", "nsaDir")
      workDir = config.get("PathVariablesLinux", "workDir")
      tempDir = config.get("PathVariablesLinux", "tempDir")


   elif(osVar == 'Windows'):
      nMAP = config.get("externalToolsWindows", "nMAP")
      xslProc = config.get("externalToolsWindows", "xslProc")

      mainDir = config.get("PathVariablesWindows", "mainDir")
      nsaDir = config.get("PathVariablesWindows", "nsaDir")
      workDir = config.get("PathVariablesWindows", "workDir")
      tempDir = config.get("PathVariablesWindows", "tempDir")
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
   checkTEMPDIR = os.path.isdir(tempDir)

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
      print('Check temp Directory ..... ' + str(checkTEMPDIR) + '\n');

   if not (checkNMAP and checkXSLPROC and checkTEMPDIR and checkWORKDIR
   and checkUID):
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
   parser.add_option("-v", action="store_true", dest="optVERB",
                     default=False, help="Schwafelmodus")
   parser.add_option("--ext", action="store_true", dest="optEXT",
                     default=False, help="DNS, OS and Version detection")
   parser.add_option("--ssl", action="store_true", dest="optSSL",
                     default=False, help="mix of SSL checks")
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

   (options, args) = parser.parse_args()
   verbose = options.optVERB
   hostonly= options.optHO

   if(options.optWAN):
      pre_switch = pre_switch + " -PE -PP --source-port 53"
      pre_switch = pre_switch + " -PS21,22,23,25,80,113,31339"
      pre_switch = pre_switch + " -PA80,113,443,10042"

   if(options.optALL):
      post_tswitch = post_tswitch + " -sS -p-"

   if (options.optEXT):
      post_switch = post_switch + " -sV --version-all -O"
   else:
      post_switch = post_switch + " -n"

   if (options.optEXT):
      post_switch = post_switch + " "

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
   print("Start Scan:")
   bashCommand = '"' + nMAP + pre_switch + " | awk '/^Nmap scan/{print $5}'" + '"'
   print(bashCommand)

   #output = subprocess.Popen([bashCommand], shell=True, stdout=subprocess.PIPE)
   #print "program output:", output



#   tempFile = tempfile.TemporaryFile(mode='w+t')
#   try:
#      tempFile.writelines(['first\n', 'second\n'])
#      tempFile.seek(0)
#
#    for line in tempFile:
#        print line.rstrip()
#
#   finally:
#      tempFile.close()
#
   #os.system(bashCommand)
   #${nMAP} ${pre_switch} | awk '/^Nmap scan/{print $5}' > ${tempFile}

   if not (hostonly):
      print("")
      #${nMAP} ${post_switch} > ${OUTPUT}.log 2> ${OUTPUT}.err
   else:
      print("")
      #mv ${tempFile} ${OUTPUT}.txt

   #rm -f ${tempFile}

#----------------------------------------------------------------------------#
# main function
def main(argv):
   print('Enhanced NMAP Reporting:\n------------------------')

   getParameter(argv)
   CheckOS()
   CheckFunction()
   nmap()

   print('ENDE ;)')

if __name__ == "__main__":
   main(sys.argv[1:])

#============================================================================#
