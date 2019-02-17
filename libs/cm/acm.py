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
from binascii import unhexlify
from datetime import datetime, timedelta
from glob import glob

class SIPReader(object):
    """
    Generator Class which extracts SIP messages from ecs log files.
    Returns a dictonary with the following key/value pairs:
    'timestamp': string in following format YYYYMMDD:hhmmssmsec
    'direction': string of 'IN' or 'OUT'
    'srcip', 'srcport': string of source IP address and int of srcport
    'dstip', 'dstport': string of destination IP address and int of dstport
    'sipmsg': string of SIP message
    """
    def __init__(self, logfiles=[], logdir='/var/log/ecs'):
        self.logdir = logdir
        self.logfiles = logfiles
        self.follow = True
        self.partial = False
        self.fragsize = 0
        self.msgsize = 0
        self.buffer = []
        self.result = {}
        self.cache = {}
        self.fd = None
        self.ecs = ''
        if self.logfiles:
            self.follow = False
            self.total = len(self.logfiles)
            try:
                self.ecs = self.logfiles.pop(0)
            except IndexError:
                raise StopIteration
            self.fd = open(self.ecs)
        else:
            self.getlog = self.iterecs(logdir=self.logdir)
            self.ecs = self.getlog.next()
            self.fd = open(self.ecs)
            self.fd.seek(0, 2)

    def __next__(self):
        while 1:
            line = self.fd.readline()
            if line:
                if self.partial:
                    if '++++' in line:
                        start = line.find('++++')
                        self.frag = line[start+6:-2].replace(' ', '')
                        self.buffer.append(self.frag)
                        self.fragsize += len(self.frag)
                    else:
                        #if the rest of the message is missing
                        self.fragsize = self.msgsize
                    if self.fragsize == self.msgsize:
                        self.partial = False
                        b = ''.join(self.buffer)
                        try:
                            self.result['sipmsg'] = unhexlify(b)
                        except:
                            #if MST line is incomplete or corrupted
                            try:
                                self.result['sipmsg'] = unhexlify(b[:-1])
                            except:
                                continue
                        return self.result
                elif '  8a ' in line or '  8b ' in line:
                    try:
                        del self.buffer[:]
                        self.fragsize = 0
                        self.result['timestamp'] = line[0:18]
                        line = line.split('MST', 1)[1][:-2].lstrip()
                        msgsize, msgbody = line.split('  ', 1)
                        self.msgsize = int(msgsize) * 2
                        self.msgbody = msgbody.replace(' ', '')
                        msgdir = (self.msgbody[0:2] == '8a') and 'IN' or 'OUT'
                        self.result['direction'] = msgdir
                        self.result.update(self._getaddr(self.msgbody[4:34]))
                        self.fragsize += len(self.msgbody)
                        self.buffer.append(self.msgbody[34:])
                        self.partial = True
                    except:
                        continue
            else:
                if not self.follow:
                    self.fd.close()
                    try:
                        self.ecs = self.logfiles.pop(0)
                    except IndexError:
                        raise StopIteration
                    self.fd = open(self.ecs)
                    break
                newecs = self.getlog.next()
                if newecs != self.ecs:
                    self.fd.close()
                    self.ecs = newecs
                    self.fd = open(self.ecs)
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

    def _getaddr(self, hexip):
        try:
            return self.cache[hexip]
        except KeyError:
            result = self.hextoaddr(hexip)
            self.cache[hexip] = result
            return result

    @staticmethod
    def hextoaddr(hexip):
        """
        Converts the hex string containing the source/destination host
        IP addresses, transport protocol and ports into a dictonary.
        :param logdir: string of MST logline from 4th to 34th bytes
        :return: dict of ip addresses, ports, protocol
        """
        srcip = '.'.join((
            str(int(hexip[0:2], 16)),
            str(int(hexip[2:4], 16)),
            str(int(hexip[4:6], 16)),
            str(int(hexip[6:8], 16))))
        srcport = int(hexip[8:12], 16)
        dstip = '.'.join((
            str(int(hexip[14:16], 16)),
            str(int(hexip[16:18], 16)),
            str(int(hexip[18:20], 16)),
            str(int(hexip[20:22], 16))))
        dstport = int(hexip[22:26], 16)
        proto = int(hexip[28:30]) > 1 and 'tls' or 'tcp'
        return {'srcip': srcip, 'srcport': srcport,
                'dstip': dstip, 'dstport': dstport,
                'proto': proto}

    @staticmethod
    def iterecs(logdir):
        """
        Infinite stateful generator which returns the ecs log files
        in sequential order created from the initialization of the
        generator object or the last ecs log file if no new one has
        been created since the last yield.
        :param logdir: string of ecs log
        :return: string of ecs filename
        """
        buf = []
        new = []
        old = sorted(glob(os.path.join(logdir, '20*')))
        try:
            buf.append(old[-1])
        except IndexError:
            raise StopIteration
        while 1:
            if buf:
                filename = buf.pop(0)
            else:
                new = glob(os.path.join(logdir, '20*'))
                diff = set(new).difference(set(old))
                buf.extend(sorted(list(diff)))
                old = new
                try:
                    filename = buf.pop(0)
                except IndexError:
                    pass
            yield filename


class ECSLogs(object):
    """
    Infinite stateful generator class which returns the ecs log files
    in sequential order created from the initialization of the class
    or returns the last ecs log file if no new one has been created since
    the last yield.
    """
    T = '(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?(\d{0,2})?'
    LOGDIR = '/var/log/ecs/'
    
    def __init__(self, logdir=None, logfiles=None, timeframe=None):
        self.logdir = logdir or self.LOGDIR
        self.logfiles = logfiles
        self.new = []
        self.reTimeframe = re.compile(self.T)
        if timeframe is not None:
            if self.logfiles is None:
                self.logfiles = glob(os.path.join(self.logdir, '20*'))
            start, sep, end = timeframe.partition('-')
            m = self.reTimeframe.search(start)
            start = datetime(*(int(x) for x in m.groups() if x))
            start = time.strftime("%Y-%m%d-%H%M%S.log", start.timetuple())
            first_index = len(self.logfiles)
            last_index = len(self.logfiles)
            try:
                first = next(x for x in self.logfiles if
                             os.path.basename(x) >= start)
                first_index = self.logfiles.index(first)
                if first_index > 0:
                    first_index -= 1
            except StopIteration:
                pass
            if end:
                m = self.reTimeframe.search(end)
                end = datetime(*(int(x) for x in m.groups() if x))
                end = time.strftime("%Y-%m%d-%H%M%S.log", end.timetuple())
                try:
                    last = next(x for x in self.logfiles if
                                os.path.basename(x) > end)
                    last_index = self.logfiles.index(last)
                except StopIteration:
                    pass
            self.logs = self.logfiles[first_index:last_index]
        elif logfiles:
            self.logs = self.logfiles
        else:
            self.old = glob(os.path.join(self.logdir, '20*'))
            self.logs = self.old[-1:]

    def __next__(self, timeframe=None, logfiles=None):
        while 1:
            if self.logfiles:
                try:
                    return self.logs.pop(0)
                except IndexError:
                    raise StopIteration
            elif self.logs:
                self.log = self.logs.pop(0)
                return self.log
            else:
                new = glob(os.path.join(self.logdir, '20*'))
                diff = set(new).difference(set(self.old))
                self.old = new
                self.logs.extend(sorted(list(diff)))
                try:
                    self.log = self.logs.pop(0)
                    return self.log
                except IndexError:
                    return self.log

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()


if __name__ == '__main__':
    sipparser = SIPReader(logfiles=['./2017-0427-090138.log'])
    print sipparser.next()
