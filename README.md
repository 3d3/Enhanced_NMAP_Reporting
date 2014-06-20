Enhanced_NMAP_Reporting
=======================

Script for Enhanced NAMP Network Reports

Features:
 - Scans 1280 IP in ~314 sec. (top 3280 Ports) and all Ports in ~3580 sec. over WAN
 - generate a html Output
 - SSL Check wir namp NSA Scripts
 - nmap-xml tp csv parser

Supported OS:
 - Linux
 - Windows

 Tested OS:
 - Fedora 20
 - Ubuntu 12.04 LTS

==============================================================================

Enhanced NMAP Reporting:
------------------------
Usage: enhancedNMAPreporting.py [options] IP-Addresses

Options:
  -h, --help       show this help message and exit
  -w, --wan        Scan over Internet
  -a, --all        scan for all ports
  -s, --ssl        mix of SSL checks
  -v               Schwafelmodus
  --ext            DNS, OS and Version detection
  --PU             UDP host detection
  --sU             UDP service scan
  --ho             Host only detection
  --customcommand  Custom nmap parameter
  --customport     Custom Ports to scan
