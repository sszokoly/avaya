#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bz2
import gzip
import os
import re
import time
from glob import glob
from textwrap import wrap
from datetime import datetime

def memoize(func):
    """A decorator to cache the return value of 'func' for a given
    input in a dictionary and returns the cached value if
    'func' is called with the same input arguments.

    Args:
        func: function to wrap with decorator

    Returns:
        wrapper: decorated function
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

class SsyndiSIPReader(object):
    """Generator class which parses SSYNDI log files, extracts CALL CONTROL
    type SIP messages and yields the SIP message body with corresponding
    host IP addresses, ports, message direction and timestamp in a
    dictionary.
    """
    LOGDIR = "/usr/local/ipcs/log/ss/logifles/elog/SSYNDI"
    SSYNDI_GLOB = "SSYNDI_*_ELOG_*"
    ADDRLINE = "IP:([a-fx0-9.]*):(\d+) --> ([a-fx0-9.]*):(\d+)"

    def __init__(self, logfiles=None, logdir=None):
        """Initializes a SsyndiSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of SSYNDI log files
                to parse, if not provided it starts reading the latest SSYNDI
                log in LOGDIR and keep doing it so when the log file rotates
            logdir (str): path to directory if SSYNDI logs are not under the
                default LOGDIR folder

        Returns:
            obj (SsyndiSIPReader): a SsyndiSIPReader class instance

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.ssyndi_glob = os.path.join(self.logdir, self.SSYNDI_GLOB)
        self.reIPs = re.compile(self.ADDRLINE)

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
            self.filename = self.last_ssyndi()
            self.fd = open(self.filename)
            self.fd.seek(0, 2)

    def __next__(self):
        """Generator"""
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
                      self.filename == self.last_ssyndi()):
                      return None
                else:
                    self.fd.close()
                    self.filename = self.last_ssyndi()
                self.fd = open(self.filename)
                readaline = self.fd.readline
            elif "SIP MSG AT CALL CONTROL" in line:
                lines = [line]
                while not lines[-1].startswith("IP:"):
                    lines.append(readaline())
                d = self.splitaddr(lines[-1])
                d["timestamp"] = self.strptime(lines[0][1:27])
                d["direction"] = lines[0][-5:-2].lstrip()
                d["sipmsg"] = "".join(lines[1:-1])
                d["proto"] = self.get_proto(d["sipmsg"])
                return d

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_ssyndi(self):
        """str: Returns the last SSYNDI log file by file name."""
        return max(x for x in glob(self.ssyndi_glob))

    @property
    def progress(self):
        """int: Returns the percentage of processed input logfiles."""
        if self.total_logfiles > 0:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @memoize
    def splitaddr(self, line):
        """Parses line argument which contains the source and destination
        host IP address and transport protocol port numbers. To speed up
        processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"srcip": <str srcip>, "srcport": <str srcport>,
                   "dstip": <str dstip>, "dstport": <str dstport>}
        """
        keys = ("srcip", "srcport", "dstip", "dstport")
        m = self.reIPs.search(line)
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
        """Converts IPv4 address from old hex to decimal format.

        Args:
            hexip (str): IPv4 address in old hex format

        Returns:
            str: IPv4 address in decimal format (xxx.xxx.xxx.xxx) 
        """
        return ".".join(str(int(x, 16)) for x in wrap(hexip[2:].zfill(8), 2))

    @staticmethod
    def get_proto(sipmsg):
        """Extracts protocol type from the top most Via header.

        Args:
            sipmsg (str): SIP message body

        Returns:
            str: Transport protocol type (UDP, TCP or TLS)
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

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime()

        Args:
            s (str): SSYNDI timestamp
 
        Returns:
            datetime obj: datetime object
        """
        return datetime(int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]))


class TracesbcSIPReader(object):
    """Generator class which parses tracesbc_sip log files and yields the
    SIP message body with corresponding host IP addresses, ports, message
    direction and timestamp in a dictionary.
    """
    LOGDIR = "/archive/log/tracesbc/tracesbc_sip"
    TRACESBCSIP_GLOB = "tracesbc_sip_[1-9][0-9][0-9]*"
    ADDRLINE = "(IN|OUT): ([0-9.]*):(\d+) --> ([0-9.]*):(\d+) \((\D+)\)" 
    
    def __init__(self, logfiles=None, logdir=None):
     """Initializes a TracesbcSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of tracesbc_sip
                log files to parse, if not provided it starts reading the
                latest tracesbc_sip log in LOGDIR and keep doing it so
                when the log file rotates
            logdir (str): path to directory if tracesbc_sip logs are not
                under the default LOGDIR folder

        Returns:
            obj (TracesbcSIPReader): a TracesbcSIPReader class instance

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.tracesbc_glob = os.path.join(self.logdir, self.TRACESBCSIP_GLOB)
        self.reIPs = re.compile(self.ADDRLINE)

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
            self.filename = self.last_tracesbc_sip()
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
                    self.filename = self.last_tracesbc_sip()
                else:
                    return None
                self.fd = self.zopen(self.filename)
                readaline = self.fd.readline
            elif line.startswith("["):
                lines = [line]
                while not lines[-1].startswith("--"):
                    lines.append(readaline().lstrip("\r\n"))
                d = self.splitaddr(lines[1])
                d["timestamp"] = self.strptime(lines[0][1:-3])
                d["sipmsg"] = "".join(x for x in lines[2:-1] if x)
                return d
    
    def __iter__(self):
        return self
    
    def next(self):
        return self.__next__()
    
    def last_tracesbc_sip(self):
        """str: Returns the last tracesbc_sip log file."""
        return max((x for x in glob(self.tracesbc_glob)))
    
    @property
    def progress(self):
        """int: Returns the percentage of processed logfiles."""
        if self.total_logfiles:
            return int(100 - (len(self.logfiles) / float(self.total_logfiles) * 100))
        return 100
    
    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses line argument which contains the source and destination
        host IP address, transport port numbers, protocol type and message
        direction. To speed up processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"direction": <str direction>, "srcip": <str srcip>,
                   "srcport": <str srcport>, "dstip": <str dstip>, 
                   "dstport": <str dstport>, "proto": <str proto>}
        """
        keys = ("direction", "srcip", "srcport", "dstip", "dstport", "proto")
        m = re.search(re.IPs, line)
        try:
            return dict((k,v) for k,v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)
    
    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime()

        Args:
            s (str): SSYNDI timestamp
 
        Returns:
            datetime obj: datetime object
        """
        return datetime(int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]))

    @staticmethod
    def zopen(filename):
        """Return file handle depending on file extension type:
        
        Args:
            filename (str): name of the logfile including path
        
        Returns:
            obj: file handler
        """
        if filename.endswith(".gz"):
            return gzip.open(filename)
        elif filename.endswith(".bz2"):
            return bz2.BZ2File(filename)
        else:
            return open(filename)

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

