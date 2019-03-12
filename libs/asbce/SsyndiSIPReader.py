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

import os
import re
import time
from glob import glob
from textwrap import wrap
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

class SsyndiSIPReader(object):
    """
    Generator class to extract CALL CONTROL SIP messages from SSYNDI logs.
    """
    
    LOGDIR = "/usr/local/ipcs/log/ss/logifles/elog/SSYNDI"
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
        return max(x for x in glob(self.ssyndi_glob))
    
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


