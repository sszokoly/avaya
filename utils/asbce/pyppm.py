#!/usr/bin/python
'''
#############################################################################
## Name: pyppm
## Description: this script parses the given ASBCE PPM log file and prints the 
## content to the stdout in a nice manner. Only works with Release 6.3 log files.
## Options: see help, -h
## Version: see option -v
## Date: 2015-09-26
## Author: szokoly@protonmail.com
#############################################################################
'''

import os
os.nice(19)
from os.path import exists
import re
import sys
import time
import gzip
import bz2
from optparse import OptionParser, SUPPRESS_HELP
try:
    import xml.etree.cElementTree as ET
    import profile
except ImportError:
    print "ERROR: This tool only works on Avaya SBCE Release 6.3 or above."
    sys.exit()

ppm_log_dir = "/archive/log/tracesbc/tracesbc_ppm/"
tracesbc_ppm_start_trigger = "["
tracesbc_ppm_end_trigger = "--"
rePPMlogfile = re.compile(r"tracesbc_ppm_(\d+){10}(.gz|.bz2)?$")
rePPMMsgType = re.compile(r"Body>[\s]*<(ns?\d+|SOAP-ENV):([a-zA-Z]*)")
rePPMhandle = re.compile(r"<n?\d?:?handle>([0-9]*)@", re.I)
rePPMgetContactListResponse = re.compile(r".*HandleSubtype></item>")
version = "1.0.1"
expiry = "191212" # YYMMDD
terse = False
printall = False
tracesbc_ppm_msg_store = []
hosts = {}
user_handle = ""

def process_ppm(tracesbc_ppm_log):
    global hosts, tracesbc_ppm_msg_store
    if tracesbc_ppm_log.endswith(".gz"):
        tracesbc_ppm_log_fd = gzip.open(tracesbc_ppm_log, "r")
    elif tracesbc_ppm_log.endswith(".bz2"):
        tracesbc_ppm_log_fd = bz2.BZ2File(tracesbc_ppm_log, "r")
    else:
        tracesbc_ppm_log_fd = open(tracesbc_ppm_log, "r")
    while True:
        line = tracesbc_ppm_log_fd.readline()
        if not line:
            tracesbc_ppm_log_fd.close()
            break
        elif line.startswith(tracesbc_ppm_start_trigger):
                handle = ""
                msgpayload = ""
                jsessionid = ""
                msgtime = line[1:-3].replace(" ", "0")
                msgclass, msgdir, src_ip_port, dst_ip_port, prot = [x.strip(":").replace("\xbb\x01", "") for x in tracesbc_ppm_log_fd.readline().split() if x != "-->"]
                line = tracesbc_ppm_log_fd.readline()
                if line.startswith("POST") or line.startswith("HTTP"):
                    httptype = line[0:4]
                    if httptype == "HTTP" and msgdir == "OUT":
                        ip = dst_ip_port.split(":")[0]
                        try:
                            handle = hosts[ip]
                        except KeyError:
                            pass
                    while not line.startswith("\r\n"):
                        line = tracesbc_ppm_log_fd.readline()
                        if line.startswith("X-Real-IP"):
                            ip = line.split()[1]
                            try:
                                handle = hosts[ip]
                            except KeyError:
                                pass
                        if line.startswith("Set-Cookie: JSESSIONID"):
                            jsessionid = line[23:55]
                            if jsessionid and handle:
                                next(x for x in reversed(tracesbc_ppm_msg_store) if x[7] == jsessionid)[9] = handle
                    while not line.startswith(tracesbc_ppm_end_trigger):
                        msgpayload += line
                        line = tracesbc_ppm_log_fd.readline()
                    if not handle and msgdir == "IN" and httptype == "POST" and rePPMhandle.search(msgpayload):
                        handle = rePPMhandle.search(msgpayload).group(1)
                        hosts.update({ip : handle})
                    ppm_msgtype = rePPMMsgType.search(msgpayload).group(2)
                    tracesbc_ppm_msg_store.append([msgclass, msgtime, msgdir, src_ip_port, dst_ip_port, prot, httptype, jsessionid, ppm_msgtype, handle, msgpayload.strip()])
                else:
                    next(x for x in reversed(tracesbc_ppm_msg_store) if (x[3], x[4]) == (src_ip_port, dst_ip_port))[-1] += line.strip()
                    
def print_ppm(tracesbc_ppm_msg_store, user_handle):
    if not printall:
        tracesbc_ppm_msg_store = [x for x in tracesbc_ppm_msg_store if ((x[2] == "IN" and x[6] == "POST") or (x[2] == "OUT" and x[6] == "HTTP")) and x[9]]
    print "\n%s\t%18s\t%7s\t%15s\t\t\t%15s\t\t%s\t\t%s\n" % ( "\033[1;37m" + "Msg No", "Date/Time", "Dir", "Src IP:Port", "Dst IP:Port", "Handle", "PPM" + "\033[0;m")
    for x in enumerate(tracesbc_ppm_msg_store):
        if not user_handle or user_handle == x[1][9] or not x[1][9]:
            print "%s\t%s  %s\t%s\t-->\t%s\t%s\t%s" % ("\033[0;m" + str(x[0]), x[1][1], x[1][2], x[1][3], x[1][4], x[1][9], "\033[1;37m" + x[1][8])
            if not terse:
                try:
                    traverse_print_xml(ET.fromstring(x[1][10]).getchildren()[-1])
                except SyntaxError:
                    print "\033[1;31m" + "Parsing error, truncated XML envelope" + "\033[0;m"
                    print x[1][10]
                print ""
    print "\033[0;m"

def traverse_print_xml(node, t=0):
    if t == 0:
        hc = "\033[0;37m"
    elif t == 1:
        hc = "\033[0;33m"
    else:
        hc = "\033[0;36m"
    for c in node.getchildren():
        if c.tag == "item":
            hc = "\033[0;36m"
        try:
            if ET.iselement(ET.fromstring(c.text)):
                traverse_print_xml(ET.fromstring(c.text), t+1)
        except:
            value = c.text and (': ' + "\033[0;32m" + c.text.strip()) or ("")
            output =  t * "  " + hc + re.sub(r"{.+?}", "", c.tag), value + "\033[0;m"
            print output[0].encode('utf8', 'replace'), output[1].encode('utf8', 'replace')
            traverse_print_xml(c, t+1)

def main():
    global user_handle, tracesbc_ppm_log, terse, printall
    parser = OptionParser(usage='%prog [<options>] [<tracesbc_ppm log file>]', description="This\
 tool parses the latest or a given PPM log file, compressed or uncompressed,\
 and displays the content in a more readable format.")
    parser.add_option('-u', action='store', default=False, dest='user_handle',\
                        help='to filter messages related to the given user handle only,\
 for example for user handle "1021@example.com" use "-u 1021"', metavar='<handle>')
    parser.add_option('-t', action='store_true', default=False, dest='terse',\
                        help='terse output, prints only a summary line per message')
    parser.add_option('-a', '--all', action='store_true', default=False, dest='printall',\
                        help='to print all messages, by default only endpoint messages are printed,\
 that is Endpoint <-> SBC Public interface')
    parser.add_option('-v', action='store_true',\
                        help='show version number and exit.')
    parser.add_option('--expiry', action='store_true', default=False, dest='expiry',\
                        help=SUPPRESS_HELP)
    opts, args = parser.parse_args()
    if opts.v:
        print version
        sys.exit()
    if os.getuid() != 0:
        print "ERROR: you must be logged in as 'root'."
        sys.exit()
    if time.time() > time.mktime(time.strptime(str(expiry), "%y%m%d")):
        print "ERROR: This tool has expired, please download a fresh copy."
        sys.exit()
    if opts.expiry:
        print time.strftime("%Y-%m-%d", time.strptime(expiry, "%y%m%d"))
        sys.exit()
    if opts.user_handle:
        user_handle = opts.user_handle
    if opts.terse:
        terse = opts.terse
    if opts.printall:
        printall = opts.printall
    if not args:
        try:
            tracesbc_ppm_log = max(ppm_log_dir + f for f in os.listdir(ppm_log_dir) if rePPMlogfile.match(f))
        except:
            print "ERROR: input file not found."
            sys.exit()
    elif exists(args[-1]):
        tracesbc_ppm_log = args[-1]
    else:
        print "ERROR: could not find this log file. Check if file exits and provide the full path."
        sys.exit()

if __name__ == "__main__":
    try:
        main()
        print "\nPPM log: %s" % tracesbc_ppm_log
        process_ppm(tracesbc_ppm_log)
        print_ppm(tracesbc_ppm_msg_store, user_handle)
        print "\033[0;m"
    finally:
        print "\033[0;m"
        try:
            sys.stdout.close()
        except:
            pass
        try:
            sys.stderr.close()
        except:
            pass