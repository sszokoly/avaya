#!/usr/bin/env python
'''
#############################################################################
## Name: session_monitor
## Description: Calculates the concurrent active sessions per interval from
##              Avaya SBCE tracesbc_sip or SSYNDI log files.
## Options: see help, -h
## Version: see help, -h
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


VERSION = 0.1
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

DESCRIPTION = '''Calculates the Peak or currently Active sessions for the
chosen interval using the SIP messages only from tracesbc_sip or SSYNDI files.
The generated  report may not be  100% accurate. Without input files provided 
as argument it parses one of the log file types mentioned above realtime. It
updates the screen with the session counts only when the specified interval
has ended  AND there was a change in the session counts during that interval
AND if there is at least one session still active in that interval. Those
still active sessions established prior to the intervals processed by this
tool are NOT counted and reported.'''

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
    For this type of messages to be logged debugging must be enabled for
    the process SSYNDI and Subsystem LOG_SUB_SIPCC.
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


class SIPSessionCounter(object):
    """
    This class keeps track of the concurrent active and peak SIP 
    sessions by parsing SIP messages received through the update 
    method. It is connection or host neutral, that is it doesn't
    care or know about the origin or destination of the message. 
    Consumers should make sure SIP messages sent to an instance
    of this class belong to the same group of connections they
    desire to track. For example messages sent to or received 
    from the same local interface, or same local or remote host 
    address or service port.
    """
    
    def __init__(self, name=None, counters=None, peak_counters=None):
        self.name = name or "SessionCounter"
        self.counters = counters or defaultdict(int)
        self.peak_counters = peak_counters or defaultdict(int)
        self._callids = {}
        self._established = set()
    
    def update(self, sipmsg, direction=None):
        """
        Receives a SIP message and returns 1 if a change has
        occurred in the counters otherwise 0.
        """
        
        rv = 0
        direction = direction or "IN&OUT"
        callid = self.get_callid(sipmsg)
        
        if not self.is_response(sipmsg):
            return rv
        
        statuscode = self.get_statuscode(sipmsg)
        cseq, method = self.get_cseq(sipmsg)
        
        if method == "INVITE":
            if statuscode == "100" and not self.is_indialog(sipmsg):
                if callid not in self._callids:
                    direction = self.reverse_direction(direction)
                    self._callids[callid] = {"direction": direction,
                                             "cseqs": set([cseq])}
                    self.counters[direction] +=1
                    rv = 1
                else:
                    direction = self._callids[callid]["direction"]
                    self._callids[callid]["cseqs"].add(cseq)
            elif (statuscode == "200" and callid in self._callids and
                  callid not in self._established):
                self._established.add(callid)
            elif (statuscode.startswith(("3", "4", "5", "6")) and
                  callid in self._callids and
                  callid not in self._established):
                self._callids[callid]["cseqs"].discard(cseq)
                if not self._callids[callid]["cseqs"]:
                    direction = self._callids[callid]["direction"]
                    self._callids.pop(callid, None)
                    self.counters[direction] -=1
                    rv = 1
        
        elif method == "BYE":
            if callid in self._established:
                direction = self._callids[callid]["direction"]
                self._established.discard(callid)
                self._callids.pop(callid, None)
                self.counters[direction] -=1
                rv = 1
        
        current = self.sessions_sum
        if self.sessions_sum > self.peak_sessions_sum:
            self.peak_counters = copy(self.counters)
        
        return rv
    
    def reset_peak(self):
        self.peak = self.sessions_sum
        self.peak_counters = copy(self.counters)
    
    def clear(self):
        self.counters.clear()
        self.reset_peak()
    
    def __add__(self, other):
        if type(self) != type(other):
            raise TypeError("can only add SIPSessionCounter to another")
        new_name = "&".join((self.name, other.name))
        new_counters = defaultdict(int)
        new_peak_counters = defaultdict(int)
        for d in self.counters, other.counters:
            for k,v in d.items():
                new_counters[k] += v
        for d in self.peak_counters, other.peak_counters:
            for k,v in d.items():
                new_peak_counters[k] += v
        return SIPSessionCounter(name=new_name, counters=new_counters,
                                 peak_counters=new_peak_counters)
    
    def __str__(self):
        return "{0} {1}  Current: {2}  Peak: {3}".format(
            self.__class__.__name__,
            self.name,
            self.sessions_sum,
            self.peak_sessions_sum)
    
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
    
    @staticmethod
    def reverse_direction(direction):
        if direction == "IN&OUT":
            return direction
        return "IN" if direction == "OUT" else "IN"
    
    @staticmethod
    def get_callid(sipmsg):
        start = sipmsg.find("Call-ID:")
        if start == -1:
            start = sipmsg.find("i:")
            if start == -1:
                return ""
            start += 3
        else:
            start += 9
        end = sipmsg.find("\n", start)
        if end == -1:
            end = None
        return sipmsg[start:end].rstrip()
    
    @staticmethod
    def get_cseq(sipmsg):
        start = sipmsg.find("CSeq:")
        if start == -1:
            return -1, ""
        start += 6
        end = sipmsg.find("\n", start)
        if end == -1:
            end = None
        l = sipmsg[start:end].split()
        if len(l) == 2:
            return int(l[0]), l[1].rstrip()
        elif len(l) == 1:
            return 0, l[0].rstrip()
        return -1, ""
    
    @staticmethod
    def get_method(sipmsg):
        end = sipmsg.find(" ")
        if space > -1:
            return sipmsg[:end]
        return ""
    
    @staticmethod
    def get_statuscode(sipmsg):
        start = sipmsg.find(" ")
        if start > -1:
            start += 1
            end = sipmsg.find(" ", start)
            return sipmsg[start:end]
        return ""
    
    @staticmethod
    def is_indialog(sipmsg):
        start = sipmsg.find("To:")
        if start == -1:
            start = sipmsg.find("t:")
            if start == -1:
                return None
        end = sipmsg.find("\n", start)
        if end == -1:
            end = None
        header = sipmsg[start:end]
        start = header.find("tag")
        if start == -1:
            return False
        return True
    
    @staticmethod
    def is_response(sipmsg):
        return sipmsg.startswith("SIP/2.0")
    
    @staticmethod
    def is_request(sipmsg):
        return not self.is_response(sipmsg)


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
        return 0
    total = 0
    column_width = 16
    left_margin = 16
    title = "{0} sessions".format("Active" if active else "Peak")
    names = ["{0}".format(title.ljust(left_margin))]
    directions = ["".ljust(left_margin)]
    values = [interval.ljust(left_margin)]
    for sc in session_counters:
        c = sc.peak_sessions if not active else sc.sessions
        names.append(sc.name.rjust(column_width))
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
    return 1

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
            if (not sipmsg.startswith("SIP/2.0") or 
                not get_cseqmethod(sipmsg).startswith(("INVITE", "BYE"))):
                continue
            
            direction = data["direction"]
            name = data["dstip"] if direction == "IN" else data["srcip"]
            if sigfilter and name not in sigfilter:
                continue
            if not verbose:
                name = interfaces.get(name, name)
            if name not in names:
                names.add(name)
                rows = max_rows
            
            timestamp = data["timestamp"].strftime("%Y%m%d:%H%M%S%f")
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

def get_cseqmethod(sipmsg):
    start = sipmsg.find("CSeq:")
    if start == -1:
        return ""
    start += 6
    end = sipmsg.find("\n", start)
    if end == -1:
        end = None
    l = sipmsg[start:end].split()
    if len(l) == 2:
        return l[1].rstrip()
    elif len(l) == 1:
        return l[0].rstrip()
    return ""

def main():
    parser = OptionParser(
        usage='%prog [<options>] [tracesbce_sip or SSYINDI files]',
        description="\n".join((DESCRIPTION, "version: " + str(VERSION))))
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
        help='to use SSYNDI instead of tracesbc_sip logs. This\
              requires debugging enabled for LOG_SUB_SIPCC Subsystem\
              for SSYNDI process')
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
    is_sbce = os.path.exists("/archive/log")
    
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
        log_dir = LOG_DIR
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
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)