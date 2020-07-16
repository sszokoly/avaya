#!/usr/bin/env python
'''
#############################################################################
## Name: find_active_calls
## Description: parses Avaya SBCE SSYNDI logs with at least LOG_SUB_SIP_B2B
##              LOG_SUB_SIPCC and LOG_SUB_SsCommon subsystems enabled and
##              returns a list of calls still counted active by the SBCE.
## Options: see help, -h
## Version: see help, -h
## Date: 2019-05-04
## Author: szokoly
#############################################################################
'''
from __future__ import print_function
import os
try:
    os.nice(19)
except:
    pass
import re
import string
import sys
from collections import deque
from datetime import datetime, timedelta
from glob import glob
from operator import itemgetter
from optparse import OptionParser, SUPPRESS_HELP

DESCRIPTION='''
Parses the Avaya SBCE SSYNDI debug logs and returns a list of calls which may 
still be counted as Active by the SBCE and which are longer than the specified
minimum duration, which is 60 mins by default.It requires  Debug level logging
enabled for subsystem: LOG_SUB_SIP_B2B, LOG_SUB_SIPCC and LOG_SUB_SsCommon.   
False positives are possible on busy systems when logging becomes unreliable.
'''
VERSION=0.2
GT=60

class linehistory(object):
    '''General purpose buffer which retains the last 'histlen' num of lines.'''
    
    def __init__(self, lines, histlen=250, history=None):
        self.lines = lines
        self.history = history or deque(maxlen=histlen)
    
    def __iter__(self):
        for line in self.lines:
            self.history.appendleft(line)
            yield line
    
    def clear(self):
        self.history.clear()


def strptime(s):
    '''
    Returns a datetime object from an ASBCE's timestamp string.
    This is 6 times faster than the standard library 
    datetime.strptime() method.
    '''
    
    return datetime(int(s[6:10]),  int(s[0:2]),   int(s[3:5]),
                    int(s[11:13]), int(s[14:16]), int(s[17:19]),
                    int(s[20:26]))

def find_ssyndis(filepat=None, path=None):
    '''Generates SSYNDI log filenames of "filepat" alike or from today'''
    
    path = path or "/archive/log/ipcs/ss/logfiles/elog/SSYNDI"
    
    if not filepat:
        today = datetime.now().strftime("%m_%d_%Y*")
        filepat = "*".join(("SSYNDI", "ELOG", today))
    
    today_glob = os.path.join(path, filepat)
    for name in sorted(glob(today_glob)):
        yield name

def ssyndi_opener(ssyndi_files, show_progress=True):
    '''Generates file handlers opened for "read" of each ssyndi_file'''
    
    for filename in ssyndi_files:
        if show_progress:
            print("Processing: {0}".format(filename), end="\r")
        with open(filename, "rt") as f:
            yield f

def gen_counter_events(ssyndi_files, show_progress=True):
    '''Generates ipcssipcTotalActiveCalls events with callid, caller number'''
    
    line_history = None
    ctxid_to_tag = {}
    tag_to_callinfo = {}
    reTags = re.compile(r"local_tag is (.*) and mRemoteTag is (.*)#")
    all = string.maketrans("", "")
    nodigs = all.translate(all, string.digits)
    ctxid_in_created_line = slice(86, 93)
    ctxid_in_destroy_line = slice(87, 94)
    timestamp_slice = slice(1, 27)
    
    for fd in ssyndi_opener(ssyndi_files, show_progress):
        lines = linehistory(fd, 210, line_history)
        for line in lines:
            
            if "sip_call_leg_t Call Leg id" in line:
                ctxid = line[ctxid_in_created_line]
                if ctxid not in ctxid_to_tag:
                    
                    tag = None
                    for hline in lines.history:
                        
                        if hline.startswith(("From:", "f:")):
                            tag = hline.split("tag=")[1].strip()
                            break
                    
                    ctxid_to_tag[ctxid] = tag
            
            elif "Incrementing counter ipcssipcTotalActiveCalls" in line:
                timestamp = line[timestamp_slice]
                tag, callid, from_num = None, None, ""
                
                for hline in lines.history:
                    
                    if hline.startswith(("Call-ID:", "i:")):
                        callid = hline.split()[1].strip()
                        if tag:
                            break
                    
                    elif hline.startswith(("From:", "f:")):
                        tag = hline.split("tag=")[1].strip()
                        start = hline.find("<")
                        end = hline.find("@", start)
                        from_num = hline[start:end].translate(all, nodigs)
                        if callid:
                            break
                
                tag_to_callinfo[tag] = (timestamp, callid, from_num)
                yield "Incrementing", (timestamp, callid, from_num)
            
            elif "Decrementing counter ipcssipcTotalActiveCalls" in line:
                loc_tag, rem_tag, tag, ctxid = None, None, None, None
                for hline in lines.history: 
                    
                    if "local_tag is" in hline:
                         loc_tag, rem_tag = reTags.search(hline[32:]).groups()
                         if loc_tag in tag_to_callinfo:
                            tag = loc_tag
                            break
                         elif rem_tag in tag_to_callinfo:
                            tag = rem_tag
                            break
                    
                    elif "is destroyed leg_count" in hline:
                        ctxid = hline[ctxid_in_destroy_line]
                        if ctxid in ctxid_to_tag:
                            t = ctxid_to_tag.pop(ctxid, None)
                            if t in tag_to_callinfo:
                                tag = t
                                break
                    
                    elif hline.startswith(("From:", "f:")):
                        from_tag = hline.split("tag=")[1].strip()
                        if from_tag in tag_to_callinfo:
                            tag = from_tag
                            break
                    
                    elif hline.startswith(("To:", "t:")):
                        to_tag = hline.split("tag=")[1].strip()
                        if to_tag in tag_to_callinfo:
                            tag = to_tag
                            break
                
                if tag:
                    yield "Decrementing", tag_to_callinfo[tag]
                    tag_to_callinfo.pop(tag, None)
                    ctxid_to_tag.pop(ctxid, None)
        
        line_history = lines.history

def main():
    parser = OptionParser(
        usage="%prog [<options>] [SSYNDI log files]",
        description="\n".join((DESCRIPTION, "version: " + str(VERSION))))
    
    parser.add_option("-c", "--callids",
        action="store_true",
        default=False,
        dest="callids",
        metavar=" ",
        help="return only the Call-IDs")
    
    parser.add_option("-f", "--froms",
        action="store_true",
        default=False,
        dest="froms",
        metavar=" ",
        help="return only the From numbers")
    
    parser.add_option("-g", "--gt",
        action="store",
        default=False,
        dest="gt",
        metavar=" ",
        help="show only the active calls with duration greater than this\
             value (in minutes). The default is 60 mins.")
    
    parser.add_option("-v", "--verbose",
        action="store_true",
        default=False,
        dest="verbose",
        metavar=" ",
        help="to turn on verbose output")
    
    opts, args = parser.parse_args()
    
    if not args:
        ssyndi_files = find_ssyndis()
    else:
        ssyndi_files = args
    
    if opts.gt:
        opts.gt = int(opts.gt)
    else:
        opts.gt = GT
    
    if opts.callids or opts.froms:
        show_progress = False
    else:
        show_progress = True
    
    calls = {}
    calls_seen = 0
    
    for event in gen_counter_events(ssyndi_files, show_progress):
        action, (timestamp, callid, from_num) = event
        
        if action == "Incrementing":
            if opts.verbose:
                print("ADDED   {0}  Call-ID {1}  From {2}".format(timestamp,
                                                           callid, from_num))
            calls[callid] = (timestamp, from_num)
            calls_seen +=1
        
        elif action == "Decrementing":
            if opts.verbose:
                timestamp, from_num = active_calls[callid]
                print("DELETED {0}  Call-ID {1}  From {2}".format(timestamp,
                                                           callid, from_num))
            del calls[callid]
    
    if not calls:
        return
    
    line_no = 1
    last_ts_strptime = strptime(timestamp)
    delta = timedelta(minutes=opts.gt)
    title = "ACTIVE CALLS WITH DURATION >{0}MINS FROM THE {1} CALLS SEEN"
    callinfo = "{0:3d}. Since {1}  with  Call-ID {2}  From {3}"
    
    if show_progress:
        print("\n\n##### ", title.format(opts.gt, calls_seen), " #####\n")
    
    filtered = filter(lambda (c,(t,f)): last_ts_strptime-strptime(t) > delta,
                                                           calls.iteritems())
    for callid, (timestamp, from_num) in sorted(filtered, key=itemgetter(1)):
        if opts.callids:
            print(callid)
        elif opts.froms:
            print(from_num)
        else:
            print(callinfo.format(line_no, timestamp, callid, from_num))
            line_no +=1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
