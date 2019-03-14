
#!/usr/bin/python
'''
#############################################################################
## Name: sipstats.py
## Description: this utility can monitor realtime or parse previous trace
## logs of Avaya Communication Manager or Avaya Session Border Controller
## for Enterprise for the purpose of providing a simply summary of the number
## of various SIP requests and responses seen on a per second, ten seconds,
## minute, ten minutes or hourly basis and or a per link basis.
## Options: see help, -h
## Version: see option -v
## Date: 2017-07-09
## Author: szokoly@protonmail.com
#############################################################################
'''
from binascii import unhexlify
from itertools import count
from glob import glob
from optparse import OptionParser
from datetime import datetime
from operator import itemgetter
from itertools import takewhile, dropwhile
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
import logging
LOG_FILENAME = "sipstatSBC.log"
logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG)
try:
    from collections import Counter
except:
    from heapq import nlargest

    class Bag(object):
        """
        Counter lass as per https://code.activestate.com/recipes/259174/
        suggested by https://docs.python.org/2/library/collections.html
        """
        def __init__(self, iterable=()):
            self._data = {}
            self._len = 0
            self.update(iterable)
        def update(self, iterable):
            if isinstance(iterable, dict):
                for elem, n in iterable.iteritems():
                    self[elem] += n
            else:
                for elem in iterable:
                    self[elem] += 1
        def __contains__(self, elem):
            return elem in self._data
        def __getitem__(self, elem):
            return self._data.get(elem, 0)
        def __setitem__(self, elem, n):
            self._len += n - self[elem]
            self._data[elem] = n
            if n == 0:
                del self._data[elem]
        def __delitem__(self, elem):
            self._len -= self[elem]
            del self._data[elem]
        def __len__(self):
            assert self._len == sum(self._data.itervalues())
            return self._len
        def __eq__(self, other):
            if not isinstance(other, Bag):
                return False
            return self._data == other._data
        def __ne__(self, other):
            if not isinstance(other, Bag):
                return True
            return self._data != other._data
        def __hash__(self):
            raise TypeError
        def __repr__(self):
            return 'bag(%r)' % self._data
        def copy(self):
            return self.__class__(self)
        __copy__ = copy  # For the copy module
        def __deepcopy__(self, memo):
            from copy import deepcopy
            result = self.__class__()
            memo[id(self)] = result
            data = result._data
            result._data = deepcopy(self._data)
            result._len = self._len
            return result
        def __getstate__(self):
            return self._data.copy(), self._len
        def __setstate__(self, data):
            self._data = data[0].copy()
            self._len = data[1]
        def clear(self):
            self._data.clear()
            self._len = 0
        def __iter__(self):
            for elem, cnt in self._data.iteritems():
                for i in xrange(cnt):
                    yield elem
        def iterunique(self):
            return self._data.iterkeys()
        def itercounts(self):
            return self._data.iteritems()
        def iteritems(self):  # added to be compatible with Counter
            return self._data.iteritems()
        def keys(self):
            return [x for x in self.iterunique()]
        def mostcommon(self, n=None):
            if n is None:
                return sorted(self.itercounts(), key=itemgetter(1), reverse=True)
            it = enumerate(self.itercounts())
            nl = nlargest(n, ((cnt, i, elem) for (i, (elem, cnt)) in it))
            return [(elem, cnt) for cnt, i, elem in nl]

    Counter = Bag

DESCRIPTION = '''
This utility can parse trace logs of Avaya Communication Manager or Avaya 
Session Border Controller for Enterprise for the purpose of providing
a simply summary of the number of SIP requests and responses seen on a
per second, ten seconds, minute, ten minutes or hourly basis.
It parses CM "ecs" or SBCE "tracesbc_sip" files. Without input log files
it runs in monitor mode until a user interrupt, CTRL^C, is received.
It is assumed that MST was set up for at least one SIP signaling-group and
it is running in this mode. The type of SIP methods and responses to monitor
and count can be defined as arguments.
'''

VERSION = 0.1
LOGDIR = '/archive/log/tracesbc/tracesbc_sip'

SAMPLING_INTERVALS = {
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
    }

SORT_ORDER = {
    'INVITE' : 0,
    'ReINVITE' : 1,
    'BYE' : 2,
    'CANCEL' : 3,
    'UPDATE' : 4,
    'NOTIFY' : 5,
    'SUBSCRIBE' : 6,
    'PUBLISH' : 7,
    'ACK' : 8,
    'PRACK' : 9,
    'REFER' : 10,
    'OPTIONS' : 11,
    'INFO' : 12,
    'PING' : 13,
    'REGISTER' : 14,
    'MESSAGE' : 15,
    'UNKOWN' : 16,
    }

DEFAULT_REQUESTS = 'INVITE|ReINVITE|BYE|CANCEL'
DEFAULT_RESPONSES = '4|5|6'

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
            logging.debug('Logfile First: %s' % self.filename)
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
                logging.debug('Line: %s' % line)
                if line:
                    if line.startswith(self.start_trigger):
                        del self.buf[:]
                        self.buf.append(line)
                        while not self.buf[-1].startswith(self.end_trigger):
                            self.buf.append(self.fd.readline())
                        ts = self.buf[0][1:-3].replace(' ', '0')
                        msgts = ''.join((
                            ts[6:10],
                            ts[0:2],
                            ts[3:5],
                            ts[10:-3].replace('.', '')))
                        msdir, srcip, srcport, dstip, dstport = splitaddr(self.buf[1])
                        logging.debug('Buf: %s' % self.buf[2:-4])
                        #for situations when message starts with empty lines
                        sipmsg = dropwhile(lambda x: x=='\r\n', self.buf[2:-4])
                        #logging.debug('Return: %s' % [tuple(sipmsg)])
                        return (msgts, msdir,
                                srcip, srcport,
                                dstip, dstport,
                                tuple(sipmsg))
                else:
                    if not self.follow:
                        logging.debug('Not Follow')
                        self.fd.close()
                        try:
                            self.filename = self.logfiles.pop(0)
                        except IndexError:
                            logging.debug('Exception')
                            raise StopIteration
                        logging.debug('Logfile Rest: %s' % self.filename)
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


class SIPStats(object):
    """

    """
    def __init__(self, requests, responses, column_width=5):
        self.d = {}
        self.requestFilter = set(requests)
        self.msgFilter = re.compile(r'(%s)' % '|'.join(requests + responses))
        self.column_width = column_width
    def add(self, srcip, srcport, dstip, dstport, sipmsg, msgdir=None):
        if isinstance(sipmsg, str):
            sipmsg = sipmsg.splitlines()
        try:
            method = next(x for x in sipmsg if x.startswith('CSeq')).split()[2]
            if sipmsg[0].startswith('SIP'):
                msgtype = sipmsg[0].split(' ', 2)[1]
            else:
                msgtype = method
                if method == 'INVITE':
                    headerTo = next(x for x in sipmsg if x.startswith('To'))
                    if 'tag=' in headerTo:
                        msgtype = 'ReINVITE'
        except StopIteration:
            method = 'UNKNOWN'
            msgtype = 'UNKNOWN'
        if int(srcport) > int(dstport):
            service_port = dstport
            if msgdir is None:
                msgdir = 'IN'
        else:
            service_port = srcport
            if msgdir is None:
                msgdir = 'OUT'
        if msgdir == 'IN':
            link = (dstip, service_port, srcip)
        else:
            link = (srcip, service_port, dstip)
        if method in self.requestFilter and self.msgFilter.match(msgtype):
            self.d.setdefault(link, {}).setdefault(msgdir, Counter()).update([msgtype])
    def clear(self):
        self.d = {}
    def summary(self):
        pass
    def __str__(self):
        msgtypes = set()
        links = {}
        output = []
        for link, msgdirs in self.d.iteritems():
            server = link[0].rjust(15)
            port = link[1].center(6, '-')
            client = link[2].ljust(15)
            link_as_string = '%s<%s>%s' % (server, port, client)
            links[link_as_string] = link
            for bag in msgdirs.values():
                msgtypes.update(bag.keys())
        requests = [x for x in list(msgtypes) if not x.isdigit()]
        requests = sorted(requests, key=lambda req: SORT_ORDER.get(req, 16))
        responses = [x for x in list(msgtypes) if x.isdigit()]
        columns = requests + sorted(responses)
        msgtype_column_title = ''.join(x.center(10) for x in columns)
        output.append(msgtype_column_title)
        subcolumns = len(columns) * ''.join(('IN'.rjust(self.column_width),
                                             'OUT'.rjust(self.column_width)))
        msgdir_column_title = ''.join((''.rjust(39), subcolumns))
        output.append(msgdir_column_title)
        for link in sorted(list(links)):
            link_columns = []
            link_columns.append(link.rjust(39))
            for column in columns:
                IN = self.d[links[link]].get('IN', Counter())[column]
                OUT = self.d[links[link]].get('OUT', Counter())[column]
                link_columns.append(str(IN))
                link_columns.append(str(OUT))
            output.append(''.join(c.rjust(self.column_width) for c in link_columns))
        output.append('')
        return '\n'.join(output)


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
    r = '(IN|OUT): (\d+\.\d+\.\d+\.\d+):(\d+) --> (\d+\.\d+\.\d+\.\d+):(\d+)'
    mdir, srcip, srcport, dstip, dstport = re.search(r, line).group(1,2,3,4,5)
    return mdir, srcip, srcport, dstip, dstport


def main():
    parser = OptionParser(
        usage='%prog [<options>] [<logfiles>]',
        description=DESCRIPTION)
    parser.add_option('--requests',
        action='store',
        default=False,
        dest='requests',
        metavar=' ',
        help='SIP request types to monitor and count.\
            default: "INVITE|ReINVITE|BYE|CANCEL",\
            alternatively "ALL".')
    parser.add_option('--responses',
        action='store',
        default=False,
        dest='responses',
        metavar=' ',
        help='SIP response types to monitor and count.\
            default: "4|5|6", for example: "182|480|5",\
            only reponses for the DEFAULT_METHODS specified\
            in "--requests" or by its default will be counted.')
    parser.add_option('-i', '--interval',
        action='store',
        default=False,
        dest='interval',
        metavar=' ',
        help='sampling interval size, can be SEC, TENSEC, MIN, TENMIN\
              HOUR or DAY, default MIN,counters are zeroed at the end\
              of the interval.')
    parser.add_option('-n',
        action='store',
        default=False,
        dest='lastx',
        metavar='<number>',
        help='parse the last "n" number of tracesbc_sip files.')
    parser.add_option('-t',
        action='store',
        default='',
        dest='tstamps',
        metavar='<start>-<end>',
        help='start/end timestamps of the period to be processed,\
        in "YYYY[mmdd:HHMMSS]" format for example for example\
        "20170731:1630-20170731:1659" or "20170730-20170731"')
    parser.add_option('-v', '--version',
        action='store_true',
        default=False,
        dest='version',
        metavar=' ',
        help='print version info.')
    opts, args = parser.parse_args()
    if opts.version:
        print 'v' + str(VERSION)
        return 0
    if opts.requests and 'ALL' in opts.requests:
        requests = SORT_ORDER.keys()
    elif opts.requests:
        requests = opts.requests.split('|')
    else:
        requests = DEFAULT_REQUESTS.split('|')
    if opts.responses:
        responses = opts.responses.split('|')
    else:
        responses = DEFAULT_RESPONSES.split('|')
    if opts.interval:
        interval = SAMPLING_INTERVALS.get(opts.interval, SAMPLING_INTERVALS['MIN'])
    else:
        interval = SAMPLING_INTERVALS['MIN']
    if os.path.exists(LOGDIR):
        sbce = True
    else:
        sbce = False
    logfiles = []
    if not sbce and not args and not opts.lastx and not opts.tstamps:
        print 'ERROR: realtime monitoring is available in ASBCE shell only!'
        return 1
    elif args or opts.lastx or opts.tstamps:
        if args:
            logs = []
            for arg in args:
                logs.extend(glob(arg))
            logfiles = [x for x in logs if os.path.isfile(x)]
        logfiles = tracesbc_sip_logs(timeframe=opts.tstamps, logfiles=logfiles)
        if logfiles and opts.lastx:
            logfiles = logfiles[-int(opts.lastx):]
        if not logfiles:
            print 'ERROR: Found no ecs log files!'
            return 2
    reader = TracesbcSIPReader(logfiles)
    stats = SIPStats(requests, responses)
    window = ''
    while 1:
        try:
            d = reader.next()
            logging.debug('In Main: %s' % [d])
            if d:
                current = d[0][interval]
                if not window:
                    window = current
                elif current != window:
                    print window.ljust(40), stats
                    stats.clear()
                    window = current
                msgts, msgdir, srcip, srcport, dstip, dstport, sipmsg = d
                stats.add(srcip, srcport, dstip, dstport, sipmsg, msgdir)
            else:
                time.sleep(0.1)
        except StopIteration:
            print window.ljust(40), stats
            return 0
        except KeyboardInterrupt:
            return 1

if __name__ == '__main__':
    sys.exit(main())

