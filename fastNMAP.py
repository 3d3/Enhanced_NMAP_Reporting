#!/usr/bin/env python

#= Enhanced NMAP Reporting - fstNMAP scan ===================================#
# author:   Markus Edelhofer
# date:     2014-06-28
#           FH Technikum Wien
#----------------------------------------------------------------------------#

__author__ = 'Markus Edelhofer'

#----------------------------------------------------------------------------#
# variables

pre_switch = "-T4 -sP -n"
post_switch = "-vv -T4 --open --host-timeout 30m -iL ${tempFile}"
post_switch = "${post_switch} -oN ${OUTPUT}.txt -oX ${OUTPUT}.xml"
post_switch = "${post_switch} -oG ${OUTPUT}_go.txt"
post_tswitch = "-sS --top-ports 3328"






#----------------------------------------------------------------------------#
# main function



#============================================================================#
