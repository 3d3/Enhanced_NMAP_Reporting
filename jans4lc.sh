#!/bin/bash

#= just another nmap scan for list creation ================================
# author:   Markus Edelhofer
# date:      2014-01-24
#            FH Technikum Wien

#= variables ===============================================================

nMAP="/usr/bin/nmap"
tempDir="/var/tmp"
xslProc="/bin/xsltproc"

#=Do not change anything below here ========================================
#= more variables ==========================================================

SOURCE=${0##*/}
OUTPUT=$(date +${SOURCE%.sh}_%Y-%m-%d_%H%M)
tempFile="${tempDir}/${SOURCE%.sh}.$$"
lanIP=false
honly=false
netw=false
dns=false

pre_switch="-T4 -sP -n"
post_switch="-vv -T4 --open --host-timeout 30m -iL ${tempFile}"
post_switch="${post_switch} -oN ${OUTPUT}.txt -oX ${OUTPUT}.xml"
post_switch="${post_switch} -oG ${OUTPUT}_go.txt"
post_tswitch="-sS --top-ports 3328"

#= function= ===============================================================

usage()
{
   printf "Usage: $0 <switch> <IP-Adresses>
   -lan   Scan in local LAN
   -wan   Scan over Internet
   -ext   DNS, OS and Version detection
   -PU    UDP host detection
   -sU    UDP service scan
   -ho    Host only detection
   -all   scan for all ports\n"
}

#= parameter ===============================================================

scan_start=$(date +%s)
while [[ -n "$1" ]]; do
   case "$1" in
      -lan)                                   # Intranet Scan
         pre_switch="${pre_switch}"
         netw=true
         shift
         ;;
      -wan)                                   # Internet Scan
         pre_switch="${pre_switch} -PE -PP --source-port 53"
         pre_switch="${pre_switch} -PS21,22,23,25,80,113,31339"
         pre_switch="${pre_switch} -PA80,113,443,10042"
         netw=true
         shift
         ;;
      -ext)                                    # OS und Version erkennung
         post_switch="${post_switch} -sV --version-all -O"
         dns=true
         shift
         ;;
      -PU)                                     # UDP Host Detection
         pre_switch="${pre_switch} -PU"
         shift
         ;;   
      -sU)                                     # UDP Service Scan only
         post_tswitch="-sU --top-ports 15094"
         shift
         ;;
      -ho)                                     # Host Only Detektion
         pre_switch="${pre_switch} -oN ${OUTPUT}.txt -oX ${OUTPUT}.xml"
         pre_switch="${pre_switch} -oG ${OUTPUT}_go.txt"
         honly=true
         shift
         ;;
      -all)                                    # scan all ports
         post_tswitch=" -sS -p-"
         shift
         ;;
      [0-9]*|*.[a-z]*)                         # IP-Adressen
         pre_switch="${pre_switch} ${1}"
         post_switch="${post_switch} ${1}"
         lanIP=true
         shift
         ;;
      *) usage
         exit 1
         ;;
   esac
done

#= program =================================================================

if [[ "$(id -u)" != "0" ]]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

if ! ${dns} ; then
   post_switch="${post_switch} -n"
fi

post_switch="${post_switch} ${post_tswitch}"

if ${netw} && ${lanIP} ; then
   ${nMAP} ${pre_switch} | awk '/^Nmap scan/{print $5}' > ${tempFile}
   if ! ${honly} ;then
      ${nMAP} ${post_switch} > ${OUTPUT}.log 2> ${OUTPUT}.err
   else
      mv ${tempFile} ${OUTPUT}.txt
   fi
   if [[ -f ${tempFile} ]];then
      rm -f ${tempFile}
   fi
else
   usage
   exit 1
fi

if [[ -f ${xslProc} ]] && ! ${honly} ;then
   ${xslProc} ${OUTPUT}.xml -o ${OUTPUT}.html 2> ${OUTPUT}.err
fi

if [[ -f ${OUTPUT}_go.txt ]];then
   cat ${OUTPUT}_go.txt \
      |grep -v ^# |grep -v "Status:" |sed 's/Host: //g; s/Ports://g' \
      |sed 's/()//g; s/\/open\/tcp\///g; s/\t/,/g; s/\/\/\///g' \
      |sed 's/ //g; s/IgnoredState:.*//g' > ${OUTPUT}_host.csv
   for i in `cat ${OUTPUT}_go.txt |grep -v ^# |grep -v "Status:" \
      |sed 's/Host: //g; s/Ports://g; s/()//g; s/\/open\/tcp\///g' \
      |sed 's/\t/,/g; s/\//,/g; s/ //g; s/IgnoredState:.*//g; s/,/\n/g' \
      |grep -v '\.' |grep [0-9]. |sort -u`
      do 
         echo -n "${i}," >> ${OUTPUT}_port.csv
         grep " ${i}/" ${OUTPUT}_go.txt |awk '{print ($2)}' \
            |sed 's/\n/,/g' | tr "\n" "," >> ${OUTPUT}_port.csv
		   echo -e "\n" >> ${OUTPUT}_port.csv
   done 
fi

scan_end=$(date +%s)
echo "Scan finished after:" $((scan_end - scan_start)) "seconds"
exit 0

#===========================================================================

