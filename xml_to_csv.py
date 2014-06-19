#!/usr/bin/env python

#= Enhanced NMAP Reporting ==================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-15
#           FH Technikum Wien
# Script Basis:
#   URI: http://blog.poultonfam.com/brad/2010/02/24/python-nmap-xml-parser/
#   Datum: 2014-06-15
#----------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer, Hannes Trunde'

import sys
import time
from array import array
from optparse import OptionParser
from xml.dom.minidom import parse, parseString

#----------------------------------------------------------------------------#
# check python version
if sys.version_info[0] != 2:
   print "\n\rThis script is only tested with Python 2.7\n\r"

#----------------------------------------------------------------------------#
# variables                # xml tag
ip = ''                    # address / addr
dnsName = ''               # hostnames
ports = []                 # port / portid
protocol = []              # port / service / name
middleware = []            # port / service / product
version = []               # port / service / version
extraInfo = []             # port / service / extrainfo  (OS ?)
sslcert = []               # script / output --> Subject
sslCommonName = []         # script / output --> Issuer ; commonName
ssldateBefore = []         # script / output --> Issuer ; Not valid before
ssldateAfter = []          # script / output --> Issuer ; Not valid after
sslSHA1 = []               # script / output --> Issuer ; SHA-1
sslenumciphers = []        #

#----------------------------------------------------------------------------#
# variables for formating
ishostname = False

#----------------------------------------------------------------------------#
# get parameter
def getParameter(argv):
   global args

   parser = OptionParser("xml_to_csv-py <file.xml>")
   (options, args) = parser.parse_args()
   if(len(args) != 1):
      print("Error: no xml-File selected!")
      sys.exit(1)

#----------------------------------------------------------------------------#
# create output
def ouput():
   global outputFile
   (prefix, sep, suffix) = args[0].rpartition('.')
   outputFileName = prefix + '.csv'
   outputFile = open(outputFileName, 'a')

#----------------------------------------------------------------------------#
# xml parser
def xmlParser(node):
   global ishostname
   global isIP
   global lastIP
   global lastHostName

   if node.nodeName == 'hostname':
      ishostname = True
      lastHostName = node.getAttribute('name')
      outputFile.write(lastHostName)
      outputFile.write(',')

   elif node.nodeName == 'address':
      if 'ip' in node.getAttribute('addrtype'):
         isIP = True
         lastIP = node.getAttribute('addr')
         outputFile.write('\n')
         outputFile.write(node.getAttribute('addr'))
         outputFile.write(',')

   elif node.nodeName == "port":
      if not isIP:
         outputFile.write(lastIP)
         outputFile.write(',')
         isIP = True
      if not ishostname:
         outputFile.write(lastHostName)
         outputFile.write(',')
         ishostname = True
      ports.append(node.getAttribute("portid"))
      outputFile.write(node.getAttribute("portid"))
      outputFile.write(',')

   elif node.nodeName == "service":
      ishostname = False
      isIP = False
      protocol.append(node.getAttribute("name"))
      outputFile.write(node.getAttribute('name'))
      outputFile.write(',')

      middleware.append(node.getAttribute("product"))
      outputFile.write(node.getAttribute('product'))
      outputFile.write(',')

      version.append(node.getAttribute("version"))
      outputFile.write(node.getAttribute('version'))
      outputFile.write(',')

      extraInfo.append(node.getAttribute("extrainfo"))
      outputFile.write(node.getAttribute('extrainfo'))
      outputFile.write(',')
      outputFile.write('\n')

   #elif node.nodeName == 'script':
      #sslcert.append(node.getAttribute("output"))
      #outputFile.write(node.getAttribute('output'))
      #outputFile.write(',')

      #sslCommonName.append(node.getAttribute("output"))
      #outputFile.write(node.getAttribute('output'))
      #outputFile.write(',')

      #ssldateBefore.append(node.getAttribute("output"))
      #outputFile.write(node.getAttribute('output'))
      #outputFile.write(',')

      #ssldateAfter.append(node.getAttribute("output"))
      #outputFile.write(node.getAttribute('output'))
      #outputFile.write(',')

      #sslSHA1.append(node.getAttribute("output"))
      #outputFile.write(node.getAttribute('output'))
      #outputFile.write(',')

#----------------------------------------------------------------------------#
# generate report
def report(args):
   global lastHostName
   xml = parse(args)

   #-------------------------------------------------------------------------#
   # head line
   outputFile.write('nmap Report:,' + time.strftime("%Y-%m-%d %H:%M") + '\n')
   outputFile.write('IP-Address,DNS-Name,Open Port(s),Protocol,Middleware,')
   outputFile.write('Version,Operating system,ssl-cert,ssl-enum-ciphers\n')

   #-------------------------------------------------------------------------#
   for node in xml.getElementsByTagName('host'):
      lastHostName = ""
      for subnode in node.childNodes:
         if subnode.attributes is not None:
            xmlParser(subnode)
            if len(subnode.childNodes) > 0:
                for subsubnode in subnode.childNodes:
                    if subsubnode.attributes is not None:
                        xmlParser(subsubnode)
                        if len(subsubnode.childNodes) > 0:
                            for subsubsubnode in subsubnode.childNodes:
                                if subsubsubnode.attributes is not None:
                                    xmlParser(subsubsubnode)
   xml.unlink()
   outputFile.close()

#----------------------------------------------------------------------------#
# run as import
def run_xml_to_csv(argv):
   getParameter(argv)
   ouput()
   report(args[0])

#----------------------------------------------------------------------------#
# main function
def main(argv):
   run_xml_to_csv(argv)

if __name__ == "__main__":
   main(sys.argv[1:])

#============================================================================#