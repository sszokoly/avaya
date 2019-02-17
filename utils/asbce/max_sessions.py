#!/usr/bin/env python
'''
#############################################################################
## Name: max_sessions
## Description: Calculates the maximum (peak) concurrent sessions per 
                interval in the Avaya SBCE parsing the tracesbc_sip messages
## Options: see help, -h
## Version: see option -v
## Date: 2018-07-01
## Author: szokoly@protonmail.com
#############################################################################
'''
import bz2
import gzip
import os
try:
    os.nice(19)
except:
    pass

import re
import sys
import time
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timedelta
from glob import glob
from itertools import dropwhile
from optparse import OptionParser

INTERVALS = {
    'S' : slice(0, 15),
    'SEC' : slice(0, 15),
    'TS' : slice(0, 14),
    'TSEC' : slice(0, 14),
    'TENSEC' : slice(0, 14),
    'M' : slice(0, 13),
    'MIN' : slice(0, 13),
    'T' : slice(0, 12),
    'TMIN' : slice(0, 12),
    'TENMIN' : slice(0, 12),
    'H' : slice(0, 11),
    'HOUR' : slice(0, 11),
    'D' : slice(0, 8),
    'DAY' : slice(0, 8),
    }

DESCRIPTION = '''Calculates the maximum concurrent session counts per interval
calculated from the SIP messages in the tracesbc_sip files. The generated 
report is not 100% accurate due to the fact that logging may be halted 
temporarily on a very busy system, though call processing continues 
unaffected.'''

class SIPMessage(object):
    def __init__(self, content):
        self._str = str(content)
    def getMethod(self):
        space = self._str.find(' ')
        if space >= 0:
            return self._str[0:space]
        return ''
    def getStatusCode(self):
        start = self._str.find(' ')
        if start >= 0:
            start += 1
            end = self._str.find(' ', start)
            return self._str[start:end]
        return ''
    def getStatusLine(self):
        start = self._str.find(' ', 8)
        if start >= 0:
            start += 1
            end = self._str.find("\r\n", start)
            return self._str[start:end]
        return ''
    def getCseqMethod(self):
        seq, method = self.getCseq()
        return method
    def getCseq(self):
        start = self._str.find('CSeq:')
        if start < 0:
            return ''
        start += 6
        end = self._str.find("\r\n", start)
        l = self._str[start:end].split()
        if len(l) == 2:
            return int(l[0]), l[1]
        elif len(l) == 1:
            return 0, l[0]
        return 0, ''
    def getHeader(self, header):
        start = self._str.find(header + ':')
        if start < 0:
            return ''
        end = self._str.find("\r\n", start)
        if end < 0:
            end = len(self._str)
        return self._str[start+len(header)+1:end].strip()
    def getHeaders(self, header):
        headers = []
        start = self._str.find(header + ':', 0)
        while start >= 0:
            end = self._str.find("\r\n", start)
            if end < 0:
                end = len(self._str)
            headers.append(self._str[start + len(header) + 1:end].strip())
            start = self._str.find(header + ':', end + 1)
        return headers
    def getHeaderUri(self, header):
        hdr = self.getHeader(header)
        if not hdr:
            return ''
        start = hdr.find('<')
        if start < 0:
            return hdr
        end = hdr.find('>', start)
        return hdr[start + 1:end]
    def getHeaderUriUser(self, header):
        uri = self.getHeaderUri(header)
        return self.getUserFromUri(uri)
    def getRequestUri(self):
        start = self._str.find(' ') + 1
        end = self._str.find(' ', start)
        uri = self._str[start:end]
        end = uri.find(';')
        if end >= 0:
            uri = uri[:end]
        return uri
    def getRequestUriUser(self):
        user = self.getRequestUri()
        start = user.find(':')
        if start >= 0:
            user = user[start + 1:]
        end = user.find('@')
        if end >= 0:
            user = user[0:end]
        else:
            end = user.find(':')
            user = user[0:end] 
        return user
    def getUserFromUri(self, uri):
        end = uri.find('@')
        if end < 0:
            return ''
        start = uri.find(':') + 1
        return uri[start:end]
    def getHdrParam(self, header, param):
        hdr = self.getHeader(header)
        start = hdr.find(param)
        if start < 0:
            return ''
        start += len(param)
        if hdr[start] == '=':
            start += 1
        end = hdr.find(';', start)
        if end < 0:
            end = len(hdr)
        if end > 0:
            return hdr[start:end]
        return ''
    def getCallId(self):
        start = self._str.find("Call-ID:")
        if start < 0:
            start = self._str.find("i:")
            if start < 0:
                return ''
            start += 3
        else:
            start += 9
        end = self._str.find("\r\n", start)
        return self._str[start:end]
    def isIndialogRequest(self):
        return self.getHdrParam("To", "tag") != ''
    def isResponse(self):
        return self._str.startswith("SIP/2.0")
    def isRequest(self):
        return not self.isResponse()
    def toStringShort(self):
        eol = self._str.find("\r\n")
        return self._str[0:eol]
    def __contains__(self, item):
        return item in self._str
    def __str__(self):
        return self._str

def get_interface_addresses():
    try:
        from netifaces import interfaces, ifaddresses, AF_INET
        ipaddresses = []
        for ifname in interfaces():
            addresses = [(i["addr"], ifname) for i in
                         ifaddresses(ifname).get(AF_INET, {})]
            ipaddresses.extend(x for x in addresses if x)
        return dict(ipaddresses)
    except:
        return None

def find_tracesbc_bytime(logfiles=None, timeframe='', type="sip"):
    logdir = "/archive/log/tracesbc/tracesbc_%s" % type
    filename_pattern = "tracesbc_%s_[1-9][0-9][0-9][0-9]*" % type
    timeframe_pattern = "(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?"
    if logfiles is None:
        path = os.path.join(logdir, filename_pattern)
        logfiles = sorted((x for x in glob(path)))
    else:
        logfiles = sorted((x for x in logfiles if
                           re.search(filename_pattern, x)))
    start, sep, end = timeframe.partition('-')
    if not start:
        return logfiles
    m = re.search(timeframe_pattern, start)
    start = datetime(*(int(x) if x else 1 for x in m.groups()))
    start = time.mktime(start.timetuple()) 
    start_epoch = str(int(start))
    try:
        first = next(x for x in logfiles if
                     os.path.basename(x)[13:24] >= start_epoch)
        first_index = logfiles.index(first)
        if first_index > 0:
            first_index -= 1
    except StopIteration:
        if logfiles and os.path.basename(logfiles[-1])[13:24] <= start_epoch:
            return logfiles[-1:]
        return []
    if end:
        m = re.search(timeframe_pattern, end)
        end = datetime(*(int(x) if x else 1 for x in m.groups()))
        end = time.mktime(end.timetuple())
        end_epoch = str(int(end))
        try:
            last = next(x for x in logfiles if
                        os.path.basename(x)[13:24] > end_epoch)
            last_index = logfiles.index(last)
        except StopIteration:
            last_index = len(logfiles)
    else:
        last_index = len(logfiles)
    return logfiles[first_index:last_index]

def splitaddr(line):
    r = "(IN|OUT): (\d+\.\d+\.\d+\.\d+):(\d+) --> (\d+\.\d+\.\d+\.\d+):(\d+) \((\D+)\)"
    m = re.search(r, line)
    if m:
        mdir, srcip, srcport, dstip, dstport, proto = m.group(1,2,3,4,5,6)
        return {"direction" : mdir, "srcip" : srcip, "srcport" : int(srcport),
                "dstip" : dstip, "dstport" : int(dstport), "proto" : proto}
    return {}

def itertracesbc(logfiles):
    start_trigger = '['
    end_trigger = '--'
    partial =  False
    buf = []
    result = {}
    cache = {}
    files_total = float(len(logfiles))
    files_read = 0
    for filename in logfiles:
        files_read += 1
        perc = str(int(files_read / files_total * 100))
        basename = os.path.basename(filename)
        prog = "Progress:%3s%%   Processing: %s\r" % (perc, basename)
        sys.stdout.write(prog)
        sys.stdout.flush()
        if filename.endswith(".gz"):
            fd = gzip.open(filename)
        elif filename.endswith(".bz2"):
            fd = bz2.BZ2File(filename)
        else:
            fd = open(filename)
        for line in fd:
            if partial:
                if line.startswith(end_trigger):
                    partial = False
                    try:
                        linkinfo = cache[buf[0]]
                    except KeyError:
                        linkinfo = splitaddr(buf[0])
                        cache[buf[0]] = linkinfo
                    result.update(linkinfo)
                    lines = dropwhile(lambda x: x=='', buf[1:-2])
                    result["sipmsg"] = ''.join(lines)
                    yield result
                else:
                    buf.append(line.lstrip("\r\n"))
            elif line.startswith(start_trigger):
                del buf[:]
                ts = line[1:-3].replace(' ', '0')
                result["timestamp"] = ''.join((ts[6:10], 
                                               ts[0:2],
                                               ts[3:5], 
                                               ts[10:-3].replace('.', '')))
                partial = True
        fd.close()

def itersessions(logfiles, interval_slice):
    sipreader = itertracesbc(logfiles=logfiles)
    callids = {}
    sessions = {}
    max_sessions = {}
    all_max_sessions = []
    interval = None
    for item in sipreader:
        timestamp = item["timestamp"]
        sipmsg = SIPMessage(item["sipmsg"])
        callid = sipmsg.getCallId()
        item_interval = timestamp[interval_slice]
        watermark = 0
        if not interval:
            interval = item_interval
        if item_interval != interval:
            all_max_sessions.append((interval, deepcopy(max_sessions)))
            max_sessions.clear()
            watermark = 0
            interval = item_interval
        if sipmsg.isRequest():
            method = sipmsg.getMethod()
            if method == "INVITE" and callid not in callids:
                direction = item["direction"]
                if direction == "IN":
                    iface = item["dstip"]
                else:
                    iface = item["srcip"]
                callids.update({callid : (iface, direction)})
                sessions.setdefault(iface, defaultdict(int))[direction] += 1
                current_max = sum(sessions[ip][dir] for ip
                                                    in sessions.iterkeys()
                                                    for dir
                                                    in sessions[ip].iterkeys()
                                                    )
                if current_max > watermark:
                   max_sessions = deepcopy(sessions)
                   watermark = current_max
            elif ((method == "CANCEL" or method == "BYE") and
                   callid in callids):
                iface, direction = callids[callid]
                sessions.setdefault(iface, defaultdict(int))[direction] -= 1
                callids.pop(callid, None)
        elif sipmsg.isResponse():
            status = sipmsg.getStatusCode()
            method = sipmsg.getCseqMethod()
            if ((method == "INVITE" and
                 status.startswith(('3','4','5','6'))) or 
                (method == "BYE")) and (callid in callids):
                iface, direction = callids[callid]
                sessions.setdefault(iface, defaultdict(int))[direction] -= 1
                callids.pop(callid, None) 
    all_max_sessions.append((interval, deepcopy(max_sessions)))
    return all_max_sessions

def max_sessions_printer(max_sessions):
    interfaces = sorted(set([i for k,v in max_sessions for i in v.keys()]))
    out = ["\n"]
    left_margin = ''.ljust(16)
    title = "Maximum Concurrent Sessions".center(len(interfaces)*16)
    out.append(''.join((left_margin, title)))
    interface_header = ''.join(x.rjust(16) for x in interfaces)
    total_header =  "Total".rjust(10)
    out.append(''.join((left_margin, interface_header, total_header)))
    a = get_interface_addresses()
    if a:
        ifname_header = ''.join(a.get(x, '').center(16) for x in interfaces)
        if ifname_header.strip():
            out.append(''.join((left_margin, ifname_header)))
    in_out_header = ''.join(("IN".rjust(8), "OUT".rjust(8)))
    out.append(''.join((left_margin, in_out_header * len(interfaces))))
    o = []
    for interval, hosts_session_counts in max_sessions:
        del o[:]
        total = 0
        o.append(interval.ljust(16))
        for interface in interfaces:
            count_in = hosts_session_counts.get(interface, {}).get("IN", 0)
            count_out = hosts_session_counts.get(interface, {}).get("OUT", 0)
            total += count_in + count_out
            o.extend([x.rjust(8) for x in str(count_in), str(count_out)])
        o.append(str(total).rjust(10))
        out.append(''.join(o))
    return "\n".join(out)

def main():
    parser = OptionParser(
        usage='%prog [<options>] [tracesbce_sip_* files]',
        description=DESCRIPTION)
    parser.add_option('-i', '--interval',
        action='store',
        default=False,
        dest='interval',
        metavar=' ',
        help='specifies the sample interval, which can be SEC,\
              TENSEC, MIN, TENMIN HOUR or DAY, the default is HOUR.')
    parser.add_option('-t', '--timeframe',
        action='store',
        default=False,
        dest='timeframe',
        metavar=' ',
        help='parses the tracesbc_sip logs for this period.\
             the format is YYYYmmdd:HHMM-[YYYYmmdd:HHMM]\
             example: "20171108:1600-20171108:1800"')
    opts, args = parser.parse_args()
    if opts.interval:
        interval_slice = INTERVALS.get(opts.interval, INTERVALS['HOUR'])
    else:
        interval_slice = INTERVALS['HOUR']
    if not args and not opts.timeframe:
        print "ERROR: no tracesbce_sip file specified, see help below!\n"
        print parser.print_help()
        return 1
    if args:
        logs = []
        for arg in args:
            logs.extend(glob(arg))
        logfiles = sorted(log for log in logs if os.path.isfile(log))
        if logfiles and opts.timeframe:
            logfiles = find_tracesbc_bytime(logfiles=logfiles,
                                            timeframe=opts.timeframe)
		if not logfiles:
			print "ERROR: Found no tracesbce_sip file, exiting!"
			return 1
    elif opts.timeframe: 
        logfiles = find_tracesbc_bytime(timeframe=opts.timeframe)
        if not logfiles:
            print "ERROR: Found no tracesbce_sip file, exiting!"
            return 1
	max_sessions = itersessions(logfiles, interval_slice)
    print max_sessions_printer(max_sessions)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print
        sys.exit(2)