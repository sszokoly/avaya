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

from glob import glob
from datetime import datetime
from itertools import dropwhile
import bz2
import gzip
import os
import re
import time
import logging
from netifaces import interfaces, ifaddresses, AF_INET

def get_interface_addresses():
    ipaddresses = []
    for ifname in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifname).get(AF_INET, {})]
        ipaddresses.extend(x for x in addresses if x)
    return ipaddresses

class TracesbcSIPReader(object):
    """
    Generator Class which extracts SIP messages from
    SBCE tracesbc_sip compressed or uncompressed log files.
    """
    def __init__(self, logfiles=None):
        self.logfiles = logfiles
        self.follow = True
        self.fd = None
        self.buf = []
        self.start_trigger = '['
        self.end_trigger = '--'
        self.filename = ''
        if self.logfiles is not None:
            self.follow = False
            self.total = len(self.logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            #logging.debug('Logfile First: %s' % self.filename)
            if self.filename.endswith('.gz'):
                self.fd = gzip.open(self.filename)
            elif self.filename.endswith('.bz2'):
                self.fd = bz2.BZ2File(self.filename)
            else:
                self.fd = open(self.filename)
        else:
            self.filename = tracesbc_sip_logs()[-1]
            self.fd = open(self.filename)
            self.fd.seek(0, 2)
    def __next__(self):
        while 1:
            while 1:
                line = self.fd.readline()
                if line:
                    if line.startswith(self.start_trigger):
                        del self.buf[:]
                        self.buf.append(line)
                        while not self.buf[-1].startswith(self.end_trigger):
                            self.buf.append(self.fd.readline().lstrip('\r\n'))
                        ts = self.buf[0][1:-3].replace(' ', '0')
                        msgts = ''.join((
                            ts[6:10],
                            ts[0:2],
                            ts[3:5],
                            ts[10:-3].replace('.', '')))
                        msdir, srcip, srcport, dstip, dstport, proto = splitaddr(self.buf[1])
                        #logging.debug('TraceSBC Before dropwhile: %s' % self.buf[2:-4])
                        sipmsg = tuple(dropwhile(lambda x: x=='', self.buf[2:-4]))
                        #logging.debug('TraceSBC Before Returning: %s' % [sipmsg])
                        return (msgts, msdir,
                                srcip, srcport,
                                dstip, dstport,
                                proto, sipmsg)
                else:
                    if not self.follow:
                        self.fd.close()
                        try:
                            self.filename = self.logfiles.pop(0)
                        except IndexError:
                            raise StopIteration
                        #logging.debug('Logfile Rest: %s' % self.filename)
                        if self.filename.endswith(".gz"):
                            self.fd = gzip.open(self.filename)
                        elif self.filename.endswith(".bz2"):
                            self.fd = bz2.BZ2File(self.filename)
                        else:
                            self.fd = open(self.filename)
                        break
                    if not os.path.exists(self.filename):
                        self.fd.close()
                        self.filename = tracesbc_sip_logs()[-1]
                        self.fd = open(self.filename)
                        break
                    else:
                        return ''
    def __iter__(self):
        return self
    def next(self):
        return self.__next__()
    @property
    def progress(self):
        if not self.follow:
            return int(100 - (len(self.logfiles) / float(self.total) * 100))
        return 100

class SIPReader(object):
    """
    Generator Class which extracts SIP messages from
    SBCE tracesbc_sip compressed or uncompressed log files.
    """
    P = '(IN|OUT): (\d+\.\d+\.\d+\.\d+):(\d+) --> (\d+\.\d+\.\d+\.\d+):(\d+) \((\D+)\)'
    def __init__(self, logfiles=None):
        self.logfiles = logfiles
        self.follow = True
        self.fd = None
        self.buf = []
        self.start_trigger = '['
        self.end_trigger = '--'
        self.filename = ''
        self.reSplitAddr = re.compile(SIPReader.P)
        self.result = {}
        if self.logfiles is not None:
            self.follow = False
            self.total = len(self.logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = self.zopen(self.filename)
        else:
            self.filename = tracesbc_sip_logs()[-1]
            self.fd = self.zopen(self.filename)
            self.fd.seek(0, 2)
    def __next__(self):
        while 1:
            line = self.fd.readline()
            if line:
                if line.startswith(self.start_trigger):
                    del self.buf[:]
                    self.buf.append(line)
                    while not self.buf[-1].startswith(self.end_trigger):
                        self.buf.append(self.fd.readline().lstrip('\r\n'))
                    ts = self.buf[0][1:-3].replace(' ', '0')
                    self.result['timestamp'] = ''.join((
                                ts[6:10], ts[0:2],
                                ts[3:5], ts[10:-3].replace('.', '')))
                    self.result.update(self.splitaddr(self.buf[1]))
                    lines = dropwhile(lambda x: x=='', self.buf[2:-4])
                    self.result['sipmsg'] = ''.join(lines)
                    return self.result
            else:
                if not self.follow:
                    self.fd.close()
                    try:
                        self.filename = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                    self.fd = self.zopen(self.filename)
                    break
                if not os.path.exists(self.filename):
                    self.fd.close()
                    self.filename = tracesbc_sip_logs()[-1]
                    self.fd = self.zopen(self.filename)
                    break
                else:
                    return ''
    def __iter__(self):
        return self
    def next(self):
        return self.__next__()
    @property
    def progress(self):
        if not self.follow:
            return int(100 - (len(self.logfiles) / float(self.total) * 100))
        return 100
    @memoize
    def splitaddr(self, line):
        """
        Splits tracesbc_sip address line up to it's constituents like
        source/destination IP address, ports and message direction.
        """
        m = self.reSplitAddr.search(line)
        try:
            mdir, srcip, srcport, dstip, dstport, proto = m.group(1,2,3,4,5,6)
        except:
            srcip, srcport, dstip, dstport = None, None, None, None
            proto, mdir = None, None
        return {'srcip' : srcip, 'srcport' : srcport, 'dstip' : dstip,
                'dstport' : dstport, 'direction' : mdir, 'proto' : proto}
    @staticmethod
    def zopen(filename):
        if filename.endswith('.gz'):
            return gzip.open(filename)
        elif filename.endswith('.bz2'):
            return bz2.BZ2File(filename)
        else:
            return open(filename)

def find_tracesbc_bytime(logfiles=None, timeframe='', type='sip'):
    logdir = '/archive/log/tracesbc/tracesbc_%s' % type
    filename_pattern = 'tracesbc_%s_[1-9][0-9][0-9][0-9]*' % type
    timeframe_pattern = '(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?'
    if logfiles is None:
        path = os.path.join(logdir, filename_pattern)
        logfiles = sorted((x for x in glob(path)))
    else:
        logfiles = sorted((x for x in logfiles if
                           re.search(filename_pattern, x)))
    start, sep, end = timeframe.partition('-')
    print start, end
    if not start:
        return logfiles
    m = re.search(timeframe_pattern, start)
    start = datetime(*(int(x) for x in m.groups() if x))
    start = time.mktime(start.timetuple())
    start_epoch = str(int(start))
    try:
        first = next(x for x in logfiles if
                     os.path.basename(x)[13:24] >= start_epoch)
        first_index = logfiles.index(first)
        if first_index > 0:
            first_index -= 1
    except StopIteration:
        return []
    if end:
        m = re.search(timeframe_pattern, end)
        end = datetime(*(int(x) for x in m.groups() if x))
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
    

def tracesbc_sip_logs(logfiles=None, timeframe=''):
    filename_pattern = r'tracesbc_sip_[1-9][0-9][0-9][0-9]*'
    timeframe_pattern = r'(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?'
    if logfiles is None:
        path = os.path.join(LOGDIR, filename_pattern)
        logfiles = sorted((x for x in glob(path)))
    else:
        logfiles = sorted((x for x in logfiles if
                           re.search(filename_pattern, x)))
    start, sep, end = timeframe.partition('-')
    if not start:
        return logfiles
    m = re.search(timeframe_pattern, start)
    start = datetime(*(int(x) for x in m.groups() if x))
    start = time.mktime(start.timetuple())
    start_epoch = str(int(start))
    try:
        first = next(x for x in logfiles if
                     os.path.basename(x)[13:24] >= start_epoch)
        first_index = logfiles.index(first)
        if first_index > 0:
            first_index -= 1
    except StopIteration:
        return []
    if end:
        m = re.search(timeframe_pattern, end)
        end = datetime(*(int(x) for x in m.groups() if x))
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


def memoize(func):
    """
    This decorator serves to cache the return value of 'func' for a given
    input in 'args' in a dictionary and returns the cached value if available
    when called with the ssme input in 'args'.
    :param func: function, it is only used with the splitaddr function
    :return: same as the return of 'func', here splitaddr() returns a
    tuple of strings.
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

@memoize
def splitaddr(line):
    """
    Splits tracesbc_sip address line up to it's constituents like
    source/destination IP address, ports and message direction.
    :param line:
    :return:
    """
    r = '(IN|OUT): (\d+\.\d+\.\d+\.\d+):(\d+) --> (\d+\.\d+\.\d+\.\d+):(\d+) \((\D+)\)'
    mdir, srcip, srcport, dstip, dstport, proto = re.search(r, line).group(1,2,3,4,5,6)
    return mdir, srcip, srcport, dstip, dstport, proto
