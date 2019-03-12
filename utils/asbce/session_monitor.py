#!/usr/bin/env python
'''
#############################################################################
## Name: session_monitor
## Description: Calculates the maximum (peak) concurrent sessions per 
                interval in the Avaya SBCE parsing the tracesbc_sip messages
## Options: see help, -h
## Version: see option -v
## Date: 2019-03-10
## Author: szokoly
#############################################################################
'''
import bz2
import gzip
import logging
import os
try:
    os.nice(19)
except:
    pass

import re
import sys
import time
from collections import defaultdict
from copy import deepcopy, copy
from datetime import datetime, timedelta
from glob import glob
from optparse import OptionParser, SUPPRESS_HELP
from textwrap import wrap
try:
    from collections import OrderedDict
except ImportError:
    from UserDict import DictMixin

    class OrderedDict(dict, DictMixin):
        '''Implement OrderedDict in python 2.4, 2.6'''
        def __init__(self, *args, **kwds):
            if len(args) > 1:
                raise TypeError('expected at most 1 arguments, got %d' % len(args))
            try:
                self.__end
            except AttributeError:
                self.clear()
            self.update(*args, **kwds)
        def clear(self):
            self.__end = end = []
            end += [None, end, end]    # sentinel node for doubly linked list
            self.__map = {}                 # key --> [key, prev, next_]
            dict.clear(self)
        def __setitem__(self, key, value):
            if key not in self:
                end = self.__end
                curr = end[1]
                curr[2] = end[1] = self.__map[key] = [key, curr, end]
            dict.__setitem__(self, key, value)
        def __delitem__(self, key):
            dict.__delitem__(self, key)
            key, prev, next_ = self.__map.pop(key)
            prev[2] = next_
            next_[1] = prev
        def __iter__(self):
            end = self.__end
            curr = end[2]
            while curr is not end:
                yield curr[0]
                curr = curr[2]
        def __reversed__(self):
            end = self.__end
            curr = end[1]
            while curr is not end:
                yield curr[0]
                curr = curr[1]
        def popitem(self, last=True):
            if not self:
                raise KeyError('dictionary is empty')
            if last:
                key = reversed(self).next()
            else:
                key = iter(self).next()
            value = self.pop(key)
            return key, value
        def __reduce__(self):
            items = [[k, self[k]] for k in self]
            tmp = self.__map, self.__end
            del self.__map, self.__end
            inst_dict = vars(self).copy()
            self.__map, self.__end = tmp
            if inst_dict:
                return (self.__class__, (items,), inst_dict)
            return self.__class__, (items,)
        def keys(self):
            return list(self)
        setdefault = DictMixin.setdefault
        update = DictMixin.update
        pop = DictMixin.pop
        values = DictMixin.values
        items = DictMixin.items
        iterkeys = DictMixin.iterkeys
        itervalues = DictMixin.itervalues
        iteritems = DictMixin.iteritems
        def __repr__(self):
            if not self:
                return '%s()' % (self.__class__.__name__,)
            return '%s(%r)' % (self.__class__.__name__, self.items())
        def copy(self):
            return self.__class__(self)
        @classmethod
        def fromkeys(cls, iterable, value=None):
            d = cls()
            for key in iterable:
                d[key] = value
            return d
        def __eq__(self, other):
            if isinstance(other, OrderedDict):
                if len(self) != len(other):
                    return False
                for p, q in  zip(self.items(), other.items()):
                    if p != q:
                        return False
                return True
            return dict.__eq__(self, other)
        def __ne__(self, other):
            return not self == other


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

LOG_DIR = "/archive/log"

DESCRIPTION = '''Calculates the Peak or currently  Active sessions for the
chosen interval from tracesbc_sip or SSYNDI files using the SIP messages only.
The generated report may not be  100% accurate. Without input files provided 
as argument it parses one of the log file types mentioned above realtime. It
updates the screen with the session counts only when the specified interval
has ended  AND there was a change in session counts during that interval.'''

def memoize(func):
    """
    A decorator to cache the return value of 'func' for a given
    input 'args' and returns the cached value when called with 
    the same input again.
    """
    cache = {}
    def wrapper(*args):
        try:
            return cache[args]
        except KeyError:
            result = func(*args)
            cache[args] = result
            return result
    return wrapper


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
            end = self._str.find("\n", start)
            return self._str[start:end].rstrip()
        return ''
    def getCseqMethod(self):
        seq, method = self.getCseq()
        return method
    def getCseq(self):
        start = self._str.find('CSeq:')
        if start < 0:
            return ''
        start += 6
        end = self._str.find("\n", start)
        l = self._str[start:end].split()
        if len(l) == 2:
            return int(l[0]), l[1].rstrip()
        elif len(l) == 1:
            return 0, l[0].rstrip()
        return 0, ''
    def getHeader(self, header):
        start = self._str.find(header + ':')
        if start < 0:
            return ''
        end = self._str.find("\n", start)
        if end < 0:
            end = len(self._str)
        return self._str[start+len(header)+1:end].rstrip()
    def getHeaders(self, header):
        headers = []
        start = self._str.find(header + ':', 0)
        while start >= 0:
            end = self._str.find("\n", start)
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
        end = self._str.find("\n", start)
        return self._str[start:end].rstrip()
    def isIndialogRequest(self):
        return self.getHdrParam("To", "tag") != ''
    def isResponse(self):
        return self._str.startswith("SIP/2.0")
    def isRequest(self):
        return not self.isResponse()
    def toStringShort(self):
        eol = self._str.find("\n")
        return self._str[0:eol].rstrip()
    def __contains__(self, item):
        return item in self._str
    def __str__(self):
        return self._str


class SIPSessionCounter(object):
    
    def __init__(self, name=None):
        self.name = name
        self.callids = {}
        self.counters = defaultdict(int)
        self.peak_counters = defaultdict(int)
        self.peak = 0
        self.inprogress = set()
        self.answered = set()
        self.ending = set()
    
    def update(self, sipmsg, direction=None):
        s = SIPMessage(sipmsg)
        direction = direction or "IN&OUT"
        callid = s.getCallId()
        
        if s.isRequest():
            method = s.getMethod()
            if method == "INVITE":
                if callid not in self.callids and not s.isIndialogRequest():
                    self.callids.update({callid : direction})
            elif method == "BYE":
                if callid in self.callids:
                    self.answered.discard(callid)
                    self.ending.add(callid)
        
        elif s.isResponse():
            if callid not in self.callids:
                return
            status = s.getStatusCode()
            method = s.getCseqMethod()
            if method == "INVITE":
                if (status.startswith("1") and not s.isIndialogRequest() 
                    and callid not in self.inprogress):
                    direction = self.callids[callid]
                    self.inprogress.add(callid)
                    self.counters[direction] +=1
                    #print "Incrementing in {0} direction: {1} callid: {2}  method: {3}  status: {4}".format(self.name, direction, callid, method, status)
                elif status == "200" and callid not in self.answered:
                    self.inprogress.discard(callid)
                    self.answered.add(callid)
                elif ((status not in ("484", )) and 
                      (status.startswith(("3", "5", "6", "4", ))) and 
                      (callid not in self.answered) and 
                      (callid in self.ending or callid in self.inprogress)):
                    direction = self.callids[callid]
                    self.inprogress.discard(callid)
                    self.ending.discard(callid)
                    self.counters[direction] -=1
                    #print "Decrementing in {0} direction: {1} callid: {2}  method: {3}  status: {4}".format(self.name, direction, callid, method, status)
                    self.callids.pop(callid, None)
            elif method == "BYE":
                if status == "200" and callid in self.ending:
                    direction = self.callids[callid]
                    self.ending.discard(callid)
                    self.counters[direction] -=1
                    #print "Decrementing in {0} direction: {1} callid: {2}  method: {3}  status: {4}".format(self.name, direction, callid, method, status)
                    self.callids.pop(callid, None)
            elif method == "CANCEL":            
                if status == "200" and callid in self.inprogress:
                    self.inprogress.discard(callid)
                    self.ending.add(callid)
        #print self.name, self.sessions, self.callids
        
        current = self.sessions_sum
        if current > self.peak:
            self.peak = current
            self.peak_counters = copy(self.counters)
    
    def reset_peak(self):
        self.peak = self.sessions_sum
        self.peak_counters = copy(self.counters)
    
    def clear(self):
        self.counters.clear()
        self.reset_peak()
    
    @property
    def sessions(self):
        return dict(self.counters)
    
    @property
    def peak_sessions(self):
        return dict(self.peak_counters)
        
    @property
    def sessions_sum(self):
        return sum(self.counters.values())
        
    @property
    def peak_sessions_sum(self):
        return sum(self.peak_counters.values())


class TracesbcSIPReader(object):
    """
    Generator class to extract SIP messages from tracesbc_sip logs.
    """
    
    LOGDIR = "/archive/log/tracesbc/tracesbc_sip"
    TRACESBC_GLOB = "tracesbc_sip_[1-9][0-9][0-9]*"
    
    def __init__(self, logfiles=None, logdir=None):
        self.logdir = logdir or self.LOGDIR
        self.tracesbc_glob = os.path.join(self.LOGDIR, self.TRACESBC_GLOB)
        if logfiles:
            self.logfiles = logfiles
            self.total_logfiles = len(logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = self.zopen(self.filename)
        else:
            self.total_logfiles = 0
            self.filename = self.tracesbc_sip_logfile
            self.fd = self.zopen(self.filename)
            self.fd.seek(0, 2)
    
    def __next__(self):
        readaline = self.fd.readline
        while True:
            line = readaline()
            if not line:
                if self.total_logfiles:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                elif not os.path.exists(self.filename):
                    self.fd.close()
                    self.filename = self.tracesbc_sip_logfile
                else:
                    return ""
                self.fd = self.zopen(self.filename)
                readaline = self.fd.readline
            elif line.startswith("["):
                lines = [line]
                while not lines[-1].startswith("--"):
                    lines.append(readaline().lstrip("\r\n"))
                d = self.splitaddr(lines[1])
                ts = lines[0][1:-3].replace(" ", "0")
                d["timestamp"] = datetime.strptime(ts, "%m-%d-%Y:%H.%M.%S.%f")
                d["sipmsg"] = "".join(x for x in lines[2:-1] if x)
                return d
    
    def __iter__(self):
        return self
    
    def next(self):
        return self.__next__()
    
    @property
    def tracesbc_sip_logfile(self):
        """
        Evaluates to the latest tracesbc_sip log file by file name.
        """
        return max((x for x in glob(self.tracesbc_glob)))
    
    @property
    def progress(self):
        """
        Returns the percentage of processed logfiles if they were provided.
        """
        if self.total_logfiles:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100
    
    @staticmethod
    @memoize
    def splitaddr(line):
        """
        Parses the line containing host port info and returns them in a dict.
        The returned value is cached by the the memoize function.
        """
        keys = ("direction", "srcip", "srcport", "dstip", "dstport", "proto")
        pattern = "(IN|OUT): ([0-9.]*):(\d+) --> ([0-9.]*):(\d+) \((\D+)\)"
        m = re.search(pattern, line)
        try:
            return dict((k,v) for k,v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)
    
    @staticmethod
    def zopen(filename):
        """
        Returns the file handler for any possible tracesbc_sip file types.
        """
        if filename.endswith(".gz"):
            return gzip.open(filename)
        elif filename.endswith(".bz2"):
            return bz2.BZ2File(filename)
        else:
            return open(filename)


class SsyndiSIPReader(object):
    """
    Generator class to extract CALL CONTROL SIP messages from SSYNDI logs.
    """
    
    LOGDIR = "/usr/local/ipcs/log/ss/logfiles/elog/SSYNDI"
    SSYNDI_GLOB = "SSYNDI_*_ELOG_*"
    
    def __init__(self, logfiles=None, logdir=None):
        self.logdir = logdir or self.LOGDIR
        self.ssyndi_glob = os.path.join(self.LOGDIR, self.SSYNDI_GLOB)
        if logfiles:
            self.logfiles = logfiles
            self.total_logfiles = len(logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = open(self.filename)
        else:
            self.total_logfiles = 0
            self.filename = self.ssyndi_logfile
            self.fd = open(self.filename)
            self.fd.seek(0, 2)
    
    def __next__(self):
        readaline = self.fd.readline
        while True:
            line = readaline()
            if not line:
                if self.total_logfiles:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                elif (os.stat(self.filename).st_size < 10482000 or
                      self.filename == self.ssyndi_logfile):
                      return ""
                else:
                    self.fd.close()
                    self.filename = self.ssyndi_logfile
                self.fd = open(self.filename)
                readaline = self.fd.readline
            elif "SIP MSG AT CALL CONTROL" in line:
                lines = [line]
                while not lines[-1].startswith("IP:"):
                    lines.append(readaline())
                d = self.splitaddr(lines[-1])
                ts = lines[0][1:27].replace(" ", "0")
                d["timestamp"] = datetime.strptime(ts, "%m-%d-%Y:%H.%M.%S.%f")
                d["direction"] = lines[0][-5:-2].lstrip()
                d["sipmsg"] = "".join(lines[1:-1])
                d["proto"] = self.get_proto(d["sipmsg"])
                return d
    
    def __iter__(self):
        return self
    
    def next(self):
        return self.__next__()
    
    @property
    def ssyndi_logfile(self):
        """
        Evaluates to the latest SSYNDI log by file name.
        """
        return max((x for x in glob(self.ssyndi_glob)), key=os.path.getmtime)
    
    @property
    def progress(self):
        """
        Returns the percentage of processed logfiles if they were provided.
        """
        if not self.total_logfiles:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100
    
    @memoize
    def splitaddr(self, line):
        """
        Parses the line containing host port info and returns them in a dict.
        The returned value is cached by the the memoize function.
        """
        keys = ("srcip", "srcport", "dstip", "dstport")
        pattern = "IP:([a-fx0-9.]*):(\d+) --> ([a-fx0-9.]*):(\d+)"
        m = re.search(pattern, line)
        try:
            d = dict((k,v) for k,v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)
        if "x" in line:
            d["srcip"] = self.hextoip(d["srcip"])
            d["dstip"] = self.hextoip(d["dstip"])
        return d
    
    @staticmethod
    def hextoip(hexip):
        """
        Converts the old hex format IP address to decimal.
        """
        return ".".join(str(int(x, 16)) for x in wrap(hexip[2:].zfill(8), 2))
    
    @staticmethod
    def get_proto(sipmsg):
        """
        Returns the protocol type from the first Via header.
        """
        start = sipmsg.find("Via:")
        if start == -1:
            start = sipmsg.find("v:")
            if start == -1:
                return "UDP"
            else:
                start += 11
        else:
            start += 13
        return sipmsg[start:start+3].upper()


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
        return {}


def find_tracesbc_bytime(logfiles=None, timeframe="", type="sip"):
    logdir = "/archive/log/tracesbc/tracesbc_%s" % type
    filename_pattern = "tracesbc_%s_[1-9][0-9][0-9][0-9]*" % type
    timeframe_pattern = "(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?"
    
    def strtepoch(s):
        m = re.search(timeframe_pattern, s)
        dt = datetime(*(int(x) if x else 1 for x in m.groups()))
        return int(time.mktime(dt.timetuple()))
    
    if logfiles is None:
        path = os.path.join(logdir, filename_pattern)
        logfiles = sorted((x for x in glob(path)))
    else:
        logfiles = sorted((x for x in logfiles if
                           re.search(filename_pattern, x)))
    
    start, sep, end = timeframe.partition('-')
    if not start:
        return logfiles
    start_epoch = str(strtepoch(start))
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
        end_epoch = str(strtepoch(end))
        try:
            last = next(x for x in logfiles if
                        os.path.basename(x)[13:24] > end_epoch)
            last_index = logfiles.index(last)
        except StopIteration:
            last_index = len(logfiles)
    else:
        last_index = len(logfiles)
    return logfiles[first_index:last_index]


def find_ssyndi_bytime(timeframe=""):
    logdir = "/usr/local/ipcs/log/ss/logfiles/elog/SSYNDI"
    ssyndi_glob = "SSYNDI_*_ELOG_*"
    pattern = "SSYNDI_\d+_ELOG_(\d+)_(\d+)_(\d+)_?(\d+)?_?(\d+)?_?(\d+)?"
    
    def order(filename):
        m = re.search(pattern, filename)
        mm, dd, yyyy, HH, MM, SS = m.groups()
        return "".join(x for x in (yyyy, mm, dd, HH, MM, SS))
    
    def is_s1gts2(ssyndi1, ssyndi2):
        return ssyndi1 == max((ssyndi1, ssyndi2), key=order)
    
    def build_name(t):
        t = t.replace(":", "")
        ph = os.path.basename(logfiles[0]).split("_", 2)[1]
        keys = ("ssyndi", "ph", "elog", "mm", "dd", "yyyy", "HH", "MM", "SS")
        d = dict(zip(("mc", "yy", "mm", "dd", "HH", "MM", "SS"), (wrap(t,2))))
        yyyy = d["mc"] + d["yy"]
        d.update({"elog": "ELOG", "ph": ph, "ssyndi": "SSYNDI", "yyyy": yyyy})
        return "_".join(x for x in (d.get(x, "00") for x in keys) if x)
    
    path = os.path.join(logdir, ssyndi_glob)
    logfiles = sorted(glob(path), key=order)
    if not logfiles:
        return []
    
    start, _, end = timeframe.partition('-')
    if not start:
        return logfiles
    s2 = build_name(start)
    l = list(filter(lambda x:is_s1gts2(os.path.basename(x), s2), logfiles))
    if not l:
        return []
    first_index = logfiles.index(l[0])  
    
    if not end:
        return logfiles[first_index:]
    s2 = build_name(end)
    l = list(filter(lambda x:is_s1gts2(os.path.basename(x), s2), logfiles))
    if not l:
        return logfiles[first_index:]
    last_index = logfiles.index(l[0])
    if last_index > 0:
        first_index -= 1
    return logfiles[first_index:last_index]


def session_counter_printer(interval, session_counters, header=0, 
                            active=False, debug=False):
    if not sum(x.peak_sessions_sum for x in session_counters):
        return False
    total = 0
    column_width = 16
    left_margin = 16
    title = "{0} sessions".format("Active" if active else "Peak")
    names = ["{0}".format(title.ljust(left_margin))]
    directions = ["".ljust(left_margin)]
    values = [interval.ljust(left_margin)]
    for sc in session_counters:
        c = sc.peak_sessions if not active else sc.sessions
        names.append(sc.name.center(column_width))
        if not c:
            directions.append("".ljust(left_margin))
            values.append("".center(left_margin))
        elif "IN&OUT" in c:
            directions.append("IN&OUT".center(column_width))
            values.append(str(c["IN&OUT"]).center(column_width))
        else:
            dirs = "".join((x.rjust(column_width/2) for x in (" IN", "OUT")))
            directions.append(dirs.center(column_width))
            IN = c.get("IN", 0)
            OUT = c.get("OUT", 0)
            total += IN + OUT
            vls = "".join((str(x).rjust(column_width/2) for x in (IN, OUT)))
            values.append(vls.center(column_width))
    names.append("Total".rjust(10))
    values.append(str(total).rjust(10))
    if not header:
        output = "".join(values)
    else:
        output = "\n".join(("".join(names),
                            "".join(directions),
                            "".join(values)))
    if debug:
        logging.info("{0}".format(output))
    print output
    return True


def itersessions(interval_slice, logfiles=None, sigfilter=None,
                 ssyndi=False, verbose=False, active=False, debug=False):
    if ssyndi or (logfiles and "SSYNDI" in logfiles[0]):
        reader = SsyndiSIPReader(logfiles=logfiles)
    else:
        reader = TracesbcSIPReader(logfiles=logfiles)
    max_rows = int(os.popen("stty size", "r").read().split()[0]) - 2
    interfaces = get_interface_addresses()
    sigfilter = set(sigfilter)
    counters = OrderedDict()
    names = set()
    rows = 0
    interval = None
    while True:
        try:
            data = reader.next()
            if not data:
                time.sleep(0.1)
                continue
            sipmsg = data["sipmsg"]
            direction = data["direction"]
            timestamp = data["timestamp"].strftime("%Y%m%d:%H%M%S%f")
            name = data["dstip"] if direction == "IN" else data["srcip"]
            if sigfilter and name not in sigfilter:
                continue
            if not verbose:
                name = interfaces.get(name, name)
            if name not in names:
                names.add(name)
                rows = max_rows
            item_interval = timestamp[interval_slice]
            if not interval:
                interval = item_interval
            if item_interval != interval:
                rv = session_counter_printer(interval, counters.values(),
                                             header=not rows%max_rows,
                                             active=active, debug=debug)
                if rv:
                    rows = 1 if rows == max_rows else rows + 1
                for counter in counters.values():
                    counter.reset_peak()
                interval = item_interval
            counters.setdefault(name, SIPSessionCounter(name)).update(sipmsg,
                                                                    direction)
        except StopIteration:
            session_counter_printer(interval, counters.values(),
                                    header=not rows%max_rows,
                                    active=active, debug=debug)
            return 0


def zopen(filename, mode="r"):
    if filename.endswith(".gz"):
        fd = gzip.open(filename, mode)
    elif filename.endswith(".bz2"):
        fd = bz2.BZ2File(filename, mode)
    else:
        fd = open(filename, mode)
    return fd


def main(log_dir):
    parser = OptionParser(
        usage='%prog [<options>] [tracesbce_sip or SSYINDI files]',
        description=DESCRIPTION)
    parser.add_option('-a', '--active',
        action='store_true',
        default=False,
        dest='active',
        metavar=' ',
        help='to show active session counts instead of peak at update')
    parser.add_option('-d', '--debug',
        action='store_true',
        default=False,
        dest='debug',
        metavar=' ',
        help=SUPPRESS_HELP)
    parser.add_option('-f',
        action='store',
        default=False,
        dest='sigfilter',
        metavar=' ',
        help='to filter interface addresses, show session counts only\
              for these IP addresses, separeted by | (pipe)')
    parser.add_option('-i', '--interval',
        action='store',
        default=False,
        dest='interval',
        metavar=' ',
        help='to specify the sample interval, which can be SEC,\
              TENSEC, MIN, TENMIN, HOUR or DAY, the default is MIN\
              for realtime monitoring, otherwise HOUR')
    parser.add_option('-n',
        action='store',
        default=False,
        dest='last',
        metavar='num',
        help='to parse the last "n" number of hours of trace files')
    parser.add_option('-s', '--ssyndi',
        action='store_true',
        default=False,
        dest='ssyndi',
        metavar=' ',
        help='to use SSYNDI instead of tracesbc_sip logs')
    parser.add_option('-t', '--timeframe',
        action='store',
        default=False,
        dest='timeframe',
        metavar=' ',
        help='to parse log files for the period specified by a\
              <start> and optional <end> date/time string as follows,\
              yyyymmdd[:HH[MM[SS]]][-yyyymmdd[:HH[MM[SS]]]]\
              for example: "20190308:0600-20190308:1800"')
    parser.add_option('-v', '--verbose',
        action='store_true',
        default=False,
        dest='verbose',
        metavar=' ',
        help='to show session counts for each IP address of the\
              interfaces instead of grouping them together')
    opts, args = parser.parse_args()
    logfiles = []
    is_sbce = os.path.exists("/archive/log/tracesbc/tracesbc_sip")
    
    if not args and not is_sbce:
        print "No trace files provided."
        return 2
    
    if args:
        logs = []
        for arg in args:
            logs.extend(glob(arg))
        logfiles = sorted(log for log in logs if os.path.isfile(log))
        if not logfiles:
            print "No trace files found."
            return 2
    elif opts.last or opts.timeframe:
        if opts.last:
            since = datetime.now() - timedelta(hours=int(opts.last))
            opts.timeframe = since.strftime("%Y%m%d:%H%M%S")
        if opts.ssyndi:
            logfiles = find_ssyndi_bytime(timeframe=opts.timeframe)
        else:
            logfiles = find_tracesbc_bytime(timeframe=opts.timeframe)
        if not logfiles:
           print "No trace files found." 
           return 2
    
    if opts.interval:
        interval_slice = INTERVALS.get(opts.interval.upper(),INTERVALS['HOUR'])
    elif not logfiles:
        interval_slice = INTERVALS['MIN']
    else:
        interval_slice = INTERVALS['HOUR']
    
    if opts.sigfilter:
        sigfilter = opts.sigfilter.split("|")
    else:
        sigfilter = []
    
    if opts.debug:
        if not is_sbce:
            log_dir = "./"
        debug_file = os.path.join(log_dir, "session_monitor")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        debug_file = debug_file + "_" + timestamp + ".log"
        logging.basicConfig(filename=debug_file, level=logging.DEBUG,
                            format="%(message)s")
    
    itersessions(interval_slice, logfiles, sigfilter, opts.ssyndi,
                 opts.verbose, opts.active, opts.debug)

if __name__ == "__main__":
    try:
        sys.exit(main(LOG_DIR))
    except KeyboardInterrupt:
        sys.exit(1)