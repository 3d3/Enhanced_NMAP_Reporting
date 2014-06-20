#!/usr/bin/env python

#= xml2csv ================================================================#
# author:   Markus Edelhofer
# author:   Hannes Trunde
# date:     2014-06-15
#           FH Technikum Wien
# Script Basis:
#   URI: http://blog.poultonfam.com/brad/2010/02/24/python-nmap-xml-parser/
#   Datum: 2014-06-15
#--------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer, Hannes Trunde'

import sys
import time
from optparse import OptionParser
from xml.dom.minidom import parse, parseString

#--------------------------------------------------------------------------#
# check python version
if sys.version_info[0] != 2:
   print "\n\rThis script is only tested with Python 2.7\n\r"

#--------------------------------------------------------------------------#
# variables for formating
ishostname = False

#--------------------------------------------------------------------------#
# get parameter
def getParameter(argv):
   global args

   parser = OptionParser("xml_to_csv-py <file.xml>")
   (options, args) = parser.parse_args()
   if(len(args) != 1):
      print("Error: no xml-File selected!")
      sys.exit(1)

#--------------------------------------------------------------------------#
# create output
def ouput():
   global outputFile
   (prefix, sep, suffix) = args[0].rpartition('.')
   outputFileName = prefix + '.csv'
   outputFile = open(outputFileName, 'a')

#--------------------------------------------------------------------------#
# xml parser
def xmlParser(node):
   global ishostname
   global isCoIu
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
         outputFile.write('\n')
         outputFile.write(lastIP)
         outputFile.write(',')
         isIP = True
      if not ishostname:
         outputFile.write(lastHostName)
         outputFile.write(',')
         ishostname = True
      outputFile.write(node.getAttribute("portid"))
      outputFile.write(',')

   elif node.nodeName == "service":
      ishostname = False
      isIP = False
      outputFile.write(node.getAttribute('name'))
      outputFile.write(',')
      outputFile.write(node.getAttribute('product'))
      outputFile.write(',')
      outputFile.write(node.getAttribute('version'))
      outputFile.write(',')
      outputFile.write(node.getAttribute('extrainfo'))
      outputFile.write(',')
      #outputFile.write('\n')

   elif node.nodeName == 'script':
      isCoIu = False
      for subnode in node.childNodes:
         if subnode.nodeName == 'table':
            if subnode.getAttribute("key") == 'subject':
               for subsubnode in subnode.childNodes:
                  if subsubnode.nodeName == 'elem':
                     if subsubnode.getAttribute("key") == 'commonName':
                        for subsubsubnode in subsubnode.childNodes:
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')

            if subnode.getAttribute("key") == 'issuer':
               for subsubnode in subnode.childNodes:
                  if subsubnode.nodeName == 'elem':
                     if subsubnode.getAttribute("key") == 'commonName':
                        for subsubsubnode in subsubnode.childNodes:
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')
                           isCoIu = True

            if subnode.getAttribute("key") == 'pubkey':
               for subsubnode in subnode.childNodes:
                  if subsubnode.nodeName == 'elem':
                     if subsubnode.getAttribute("key") == 'bits':
                        for subsubsubnode in subsubnode.childNodes:
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')
                     if subsubnode.getAttribute("key") == 'type':
                        for subsubsubnode in subsubnode.childNodes:
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')

            if subnode.getAttribute("key") == 'validity':
               for subsubnode in subnode.childNodes:
                  if subsubnode.nodeName == 'elem':
                     if subsubnode.getAttribute("key") == 'notBefore':
                        for subsubsubnode in subsubnode.childNodes:
                           if not isCoIu:
                              outputFile.write(',')
                              isCoIu = True;
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')
                     if subsubnode.getAttribute("key") == 'notAfter':
                        for subsubsubnode in subsubnode.childNodes:
                           if not isCoIu:
                              outputFile.write(',')
                              isCoIu = True;bits
                           outputFile.write(subsubsubnode.nodeValue)
                           outputFile.write(',')

         if subnode.nodeName == 'elem':
            if subnode.getAttribute("key") == 'sha1':
              for subsubnode in subnode.childNodes:
                 outputFile.write(subsubnode.nodeValue)
                 outputFile.write(',')

#--------------------------------------------------------------------------#
# generate report
def report(args):
   global lastHostName
   xml = parse(args)

   #-----------------------------------------------------------------------#
   # head line
   outputFile.write('nmap Report:,' + time.strftime("%Y-%m-%d %H:%M") +
                    '\n')
   outputFile.write('IP-Address,DNS-Name,Open Port(s),Protocol,Middleware,'
                    'Version,Operating system,ssl-commonName (cn),'
                    'ssl-issuer-ca,pubkey length,pubkey type,notBefore,'
                    'notAfter,SHA1,\n')

   #-----------------------------------------------------------------------#
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
                     if len(subsubsubnode.childNodes) > 0:
                       for subsubsubsubnode in subsubsubnode.childNodes:
                         if subsubsubsubnode.attributes is not None:
                           xmlParser(subsubsubsubnode)
   xml.unlink()
   outputFile.close()

#--------------------------------------------------------------------------#
# run as import
def run_xml_to_csv(argv):
   ouput()
   report(args[0])

#--------------------------------------------------------------------------#
# main function
def main(argv):
   getParameter(argv)
   run_xml_to_csv(argv)

if __name__ == "__main__":
   main(sys.argv[1:])

#==========================================================================#
