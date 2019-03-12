"""
Copyright 2018 Szabolcs Szokoly <szokoly@protonmail.com>
This file is part of szokoly.
szokoly is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
szokoly is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with szokoly.  If not, see <http://www.gnu.org/licenses/>.
"""

import bz2
import gzip
import os
import re
import time
from glob import glob
from datetime import datetime

def memoize(func):
    """
    A decorator to cache the return value of 'func' for a given
    input 'args' in a dictionary and returns the cached value if
    available when called with the same input again.
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

