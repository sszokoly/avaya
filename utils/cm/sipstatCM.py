#!/usr/bin/python
'''
##############################################################################
## Name: sipstatCM.py
## Description: this utility can monitor realtime or parse previous ecs log
## files of Avaya Communication Manager for the purpose of providing a simply
## summary of the number of various SIP requests and responses on a per second
## ten seconds, minute, ten minutes or hourly basis.
## Options: see help, -h
## Version: see option -v
## Date: 2017-11-27
## Author: sszokoly@prontonmail.com
##############################################################################
'''
from binascii import unhexlify
from itertools import count
from glob import glob
from optparse import OptionParser
import os
try:
    os.nice(19)
except:
    pass
import re
import sys
import time

DESCRIPTION = '''
This utility can parse ecs log files of Avaya Communication Manager
for the purpose of providing a simply summary of the number of SIP
requests and responses on a per second, ten seconds, minute, ten 
minutes or hourly basis. Without input files it runs in monitor mode
until a user interrupt, CTRL^C, is received. It is assumed that MST
was set up for at least one SIP signaling-group and it is running
in this mode. The type of SIP methods and responses to count can be
defined as command line options.
'''

VERSION = 0.1
LOGDIR = '/var/log/ecs'

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
    }

DEFAULT_METHODS = [
    'INVITE',
    'ReINVITE',
    'BYE',
    'CANCEL',
    ]

DEFAULT_RESPONSES = [
    '4',
    '5',
    '6',
    ]

# CM6.x is still using Python 2.4 which doesn't have next() builtin.
if not hasattr(__builtins__, 'next'):
    def next(iterable):
        return iterable.next()

class ECSSipParser(object):
    """
    This is a generator class which extracts SIP messages from Avaya
    Communication Manager ecs log files. If instantiated without a list
    of ecs log files then it will monitor and parse the last ecs log file
    realtime. For example to print SIP messages realtime on an ACM server:

    parser = ECSSipParser()
    while true:
        msg = parser.next()
        if msg:
            print msg   #this prints the tuple of related information
        else:
            time.sleep(0.1)
    """
    def __init__(self, logfiles=[]):
        """"
        :param logfiles: list, optional list of ecs log files to parse
        """
        self.logdir= LOGDIR
        self.logfiles = logfiles
        self.dmap = {'8a' : 'IN', '8b' : 'OUT'} # SIP message direction
        self.follow = True #True = realtime monitoring
        self.partial = False #if SIP message spreads over multiple lines
        self.fragsize = 0 #current SIP message size joint together so far
        self.msgsize = 0 #expected total SIP message size provided ahead
        self.buf = []
        self.fd = None
        self.filename = ''
        if self.logfiles:
            self.follow = False
            self.total = len(self.logfiles)
            try:
                self.filename = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = open(self.filename)
        else:
            self.ecslog = self.get_last_ecs(self.logdir)
            self.filename = self.ecslog.next()
            self.fd = open(self.filename)
            self.fd.seek(0, 2)

    def __next__(self):
        while 1:
            while 1:
                line = self.fd.readline()
                if line:
                    if self.partial:
                        if '++++' in line:
                            self.frag = line.split('++++')[1][2:-2].replace(' ', '')
                            self.buf.append(self.frag)
                            self.fragsize += len(self.frag)
                        else:
                            #if MST line is incomplete or corrupted
                            self.fragsize = self.msgsize
                        if self.fragsize == self.msgsize:
                            self.partial = False
                            b = ''.join(self.buf)
                            try:
                                self.msg = unhexlify(b)
                            except:
                                #if MST line is incomplete or corrupted
                                try:
                                    self.msg = unhexlify(b[:-1])
                                except:
                                    continue
                            return (self.msgts, self.msgdir,
                                    self.srcip, self.srcport,
                                    self.dstip, self.dstport,
                                    self.msg.split('\r\n'))
                    elif '  8a ' in line or '  8b ' in line:
                        try:
                            del self.buf[:]
                            self.fragsize = 0
                            self.msgts = line[0:18]
                            line = line.split('MST', 1)[1][:-2].lstrip()
                            self.msgsize, self.msgbody = line.split('  ',1)
                            self.msgsize = int(self.msgsize) * 2
                            self.msgbody = self.msgbody.replace(' ', '')
                            self.msgdir = self.dmap[self.msgbody[0:2]]
                            srcip_port, dstip_port = hex2ip(self.msgbody[4:30])
                            self.srcip, self.srcport = srcip_port
                            self.dstip, self.dstport = dstip_port
                            self.fragsize += len(self.msgbody)
                            self.buf.append(self.msgbody[34:])
                            self.partial = True
                        except:
                            continue
                else:
                    if not self.follow:
                        self.fd.close()
                        try:
                            self.filename = self.logfiles.pop(0)
                        except IndexError:
                            raise StopIteration
                        self.fd = open(self.filename)
                        break
                    newfilename = self.ecslog.next()
                    if newfilename:
                        self.fd.close()
                        self.filename = newfilename
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
        '''
        Progress indicator which provides the % of input files already processed.
        :return: int, percentage of processed file of the total provided
        '''
        if not self.follow:
            return int(100 - (len(self.logfiles) / float(self.total) * 100))
        return 100

    @staticmethod
    def get_last_ecs(logdir=LOGDIR):
        '''
        Simple generator which keeps track of the ACM ecs log files and
        returns them one by one when called in an orderly manner
        regardless of how much time has passed between the calls.
        :param logdir: string, it is '/var/log/ecs' by default
        :return: string, the full path of the next ecs log file to be processed
        '''
        logs = []
        new = []
        old = sorted(glob(os.path.join(logdir, '20*')))
        try:
            logs.append(old[-1])
        except IndexError:
            yield ''
        while 1:
            if logs:
                yield logs.pop(0)
            else:
                new = glob(os.path.join(logdir, '20*'))
                diff = set(new).difference(set(old))
                old = new
                logs.extend(sorted(list(diff)))
                try:
                    yield logs.pop(0)
                except IndexError:
                    yield ''


class SIPStats(object):
    '''
    Count SIP message types and stores them in the "self.data" dictionary
    grouped by communication link and message direction.
    '''
    def __init__(self, methods=DEFAULT_METHODS, responses=DEFAULT_RESPONSES):
        self.data = {}
        self.methodsOfIntertest = set(methods)
        self.reInterest = re.compile(r'(%s)' % '|'.join(methods + responses))
    def add(self, msgts, msgdir, srcip, srcport, dstip, dstport, lines):
        cseqline = next(x for x in lines if x.startswith('CSeq'))
        cseqno, method = cseqline.split()[1:3]
        if lines[0].startswith('SIP'):
            msgtype = lines[0].split(' ', 2)[1]
            trk = (srcip, srcport, dstip)
        else:
            msgtype = lines[0].split(' ', 1)[0]
            trk = (dstip, dstport, srcip)
            if msgtype == 'INVITE':
                toline = next(x for x in lines if x.startswith('To'))
                if 'tag=' in toline:
                    msgtype = 'ReINVITE'
        if method in self.methodsOfIntertest and self.reInterest.match(msgtype):
            self.data.setdefault(trk, {}).setdefault(msgdir, {}).setdefault(msgtype, count(0)).next()
    def clear(self):
        self.data = {}
    def __str__(self):
        c = set()
        t = {}
        output = []
        for trktup, val in self.data.iteritems():
            trunk_ipaddr_port = sorted(list(trktup))
            ip1 = trunk_ipaddr_port[0].rjust(15)
            ip2 = trunk_ipaddr_port[1].ljust(15)
            port = trunk_ipaddr_port[2].center(6, '-')
            trk = '%s<%s>%s' % (ip1, port, ip2)
            t[trk] = trktup
            for d in val.values():
                c.update(d.keys())
        requests = [x for x in list(c) if not x.isdigit()]
        responses = [x for x in list(c) if x.isdigit()]
        requests = sorted(requests, key=lambda r: SORT_ORDER.get(r, 16))
        col = requests + sorted(responses)
        columns = ''.join(x.center(10) for x in col)
        output.append(columns)
        subcolumns = len(col) * ''.join(('IN'.rjust(5), 'OUT'.rjust(5)))
        output.append(''.join((''.rjust(39), subcolumns)))
        for trk in sorted(list(t)):
            l = []
            l.append(trk.rjust(39))
            for header in col:
                IN = self.data[t[trk]].get('IN', {}).get(header, count(0))
                OUT = self.data[t[trk]].get('OUT', {}).get(header, count(0))
                l.append(str(next(IN)))
                l.append(str(next(OUT)))
            output.append(''.join(c.rjust(5) for c in l))
        output.append('')
        return '\n'.join(output)

def memoize(func):
    '''
    This decorator serves to cache the return value of 'func' for a given
    input in 'args' in a dictionary and returns the cached value if available
    when called with the ssme input in 'args'.
    It is used to cache the hex IP,PORT values of a SIP message as keys and
    return the corresponding IP,PORT values in decimal.
    :param func: function, it is only used for the hex2ip function here
    :return: function, a wrapped function
    '''
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
def hex2ip(hexip):
    '''
    Convert the string containing the hex IP,PORT of source/destination hosts
    to two tuples, each with decimal IP, PORT of the host.
    :param hexip: string, source IP:PORT and destination IP:PORT in hex
    :return: tuple of two tuples of strings
    '''
    hexip = hexip.replace(' ', '')
    srcip = '.'.join((
        str(int(hexip[0:2], 16)),
        str(int(hexip[2:4], 16)),
        str(int(hexip[4:6], 16)),
        str(int(hexip[6:8], 16)),
            ))
    srcport = str(int(hexip[8:12], 16))
    dstip = '.'.join((
        str(int(hexip[14:16], 16)),
        str(int(hexip[16:18], 16)),
        str(int(hexip[18:20], 16)),
        str(int(hexip[20:22], 16)),
            ))
    dstport = str(int(hexip[22:26], 16))
    return (srcip, srcport), (dstip, dstport)

def convert_tstamp(t):
    '''
    Covert a list of 'YYYY[mmdd:HHMM]' to 'YYYY-[mmdd-HHmm]' string to ecs log file names.
    :param t: list, list of strings in 'YYYYmmdd:HHmm' format
    :return: list, list of strings in 'YYYY-mmdd-HHmm' format
    '''
    l = []
    for ts in t:
        m = re.search(r'(\d{4})(\d{0,4})?:?(\d{0,6})?', ts)
        if m:
            l.append('-'.join(x for x in m.groups() if x))
    return l

def main():
    parser = OptionParser(
        usage='%prog [<options>] [logfiles]',
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
        help='can be SEC, TENSEC, MIN, TENMIN or HOUR, default MIN,\
              the size of the interval when counters are zeroed.')
    parser.add_option('-n',
        action='store',
        default=False,
        dest='lastx',
        metavar='<number>',
<<<<<<< HEAD
        help='parse the last "n" number of ecs files.')
=======
        help='parse the last "n" number of ecs log files.')
>>>>>>> 06ca9323c4a50d408f0b96412436069082bfcc63
    parser.add_option('-t',
        action='store',
        default=False,
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
        requests = DEFAULT_METHODS
    if opts.responses:
        responses = opts.responses.split('|')
    else:
        responses = DEFAULT_RESPONSES
    if opts.interval:
        interval = INTERVALS.get(opts.interval, INTERVALS['MIN'])
    else:
        interval = INTERVALS['MIN']
    if os.path.exists(LOGDIR):
        acm = True
    else:
        acm = False
    logfiles = []
    if not acm and not args and not opts.lastx and not opts.tstamps:
        print 'ERROR: realtime monitoring is available in ACM shell only!'
        return 1
    elif args or opts.lastx or opts.tstamps:
        if args:
            logs = []
            for arg in args:
                logs.extend(glob(arg))
            logfiles = sorted(log for log in logs if os.path.isfile(log))
        else:
            if acm:
                path = os.path.join(LOGDIR, '20*')
            else:
                path = ''.join((os.getcwd(), os.sep, '20*'))
            logfiles = sorted(glob(path))
        if logfiles and opts.lastx:
            logfiles = logfiles[-int(opts.lastx):]
        elif logfiles and opts.tstamps:
            low, high = convert_tstamp(opts.tstamps.split('-'))
            try:
                first = next(x for x in logfiles if os.path.basename(x)[0:len(low)] >= low)
                first_index = logfiles.index(first)
                if first_index > 0:
                    first_index -=1
            except StopIteration:
                first_index = len(logfiles)
            try:
                last = next(x for x in logfiles if os.path.basename(x)[0:len(high)] > high)
                last_index = logfiles.index(last)
            except StopIteration:
                last_index = len(logfiles)
            logfiles = logfiles[first_index:last_index]
        if not logfiles:
            print 'ERROR: Found no ecs log files!'
            return 2
    parser = ECSSipParser(logfiles)
    stats = SIPStats(requests, responses)
    window = ''
    while 1:
        try:
            d = parser.next()
            if d:
                current = d[0][interval]
                if not window:
                    window = current
                elif current != window:
                    print window.ljust(40), stats
                    stats.clear()
                    window = current
                stats.add(*d)
            else:
                time.sleep(0.1)
        except StopIteration:
            print window.ljust(40), stats
            return 0
        except KeyboardInterrupt:
            return 1

if __name__ == '__main__':
    sys.exit(main())
