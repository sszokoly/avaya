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


FORMAT="""display system-parameters cdr                       Page   2 of   2
                            CDR SYSTEM PARAMETERS

     Data Item - Length         Data Item - Length         Data Item - Length
 1: date             - 6   17: calling-num      - 11  33:                  -
 2: space            - 1   18: space            - 1   34:                  -
 3: time             - 4   19: auth-code        - 8   35:                  -
 4: space            - 1   20: space            - 1   36:                  -
 5: sec-dur          - 5   21: acct-code        - 4   37:                  -
 6: space            - 1   22: space            - 1   38:                  -
 7: cond-code        - 1   23: in-crt-id        - 3   39:                  -
 8: space            - 1   24: space            - 1   40:                  -
 9: code-dial        - 4   25: out-crt-id       - 3   41:                  -
10: space            - 1   26: space            - 1   42:                  -
11: code-used        - 4   27: vdn              - 5   43:                  -
12: space            - 1   28: space            - 1   44:                  -
13: in-trk-code      - 4   29: frl              - 1   45:                  -
14: space            - 1   30: return           - 1   46:                  -
15: dialed-num       - 18  31: line-feed        - 1   47:                  -
16: space            - 1   32:                  -     48:                  -

                              Record length = 97
"""

class CDRReader(object):
    """
    Extracts CDR records from various types of input files.
    The following input files are supported:
    txtfiles=[<list of text files containing the CDR record>]
    mstfiles=[<list of mta decoded mst files>]
    ecsfiles=[<list of ecs log files>]
    The format of the CDR record is specified in the "format"
    argument which is the copy of the "display system-parameters cdr"
    page 2. See example in FORMAT above.
    With the optional "stdout" argument the filename that is being
    processed can be printed to stdout.
    Output: the cdr record as string

    Usage example:
    
    from glob import glob
    reader = CDRReader(format=FORMAT, ecsfiles=glob("./2*.log"))
    for record in reader:
        print record, reader.timestamp
    
    """
    def __init__(self, format, stdout=False, 
                       txtfiles=None, ecsfiles=None, mstfiles=None):
        self.format = format
        self.stdout = stdout
        self.txtfiles = txtfiles
        self.ecsfiles = ecsfiles
        self.mstfiles = mstfiles
        self.parsed_format = self.parse_format(self.format)
        self.timestamp = None
        self._items = None
        self._slices = None
        self.length = self.slices[-1].stop
        self.zipped = dict(zip(self.items, self.slices))
        if self.txtfiles is not None:
            self.reader = self.txtreader(txtfiles, stdout=self.stdout)
        elif self.ecsfiles is not None:
            self.reader = self.ecsreader(ecsfiles, stdout=self.stdout)
        elif self.mstfiles is not None:
            self.reader = self.mstreader(mstfiles, stdout=self.stdout)
        else:
            out = "%s class instance requires one inputfile list (0 given)"
            raise TypeError(out % type(self).__name__)

    @property
    def items(self):
        if self._items is None:
            self._items = tuple(x[0] for x in self.parsed_format)
        return self._items

    @property
    def slices(self):
        if self._slices is None:
            self._slices = tuple(x[1] for x in self.parsed_format)
        return self._slices

    @staticmethod   
    def parse_format(format):
        l = []
        fields = sorted([(int(x[0]), x[1], int(x[2])) for x in
                          re.findall(r"(\d+): (\S+).+?- (\d+)", format)])
        for i,name,length in fields:
            end = sum(x[2] for x in fields[0:i])
            l.append((name, slice(end-length, end)))
        return l

    def __iter__(self):
        return self

    def __next__(self):
        self.record, self.timestamp = self.reader.next()
        return self.record

    def next(self):
        return self.__next__()

    def __len__(self):
        return self.length

    def txtreader(self, txtfiles, stdout=False):
        ft = "%d%m%y%H%M%S"
        for txtfile in txtfiles:
            if stdout:
                sys.stdout.write("Processing: %s\r" % txtfile)
                sys.stdout.flush()
            try:
                fd = open(txtfile, "rb")
            except:
                continue
            for line in fd:
                record = "".join(x for x in line if x in string.printable)
                if len(record) < self.length-1:
                    continue
                ddmmyy = record[self.zipped.get('date', slice(0, 0))]
                HHMM = record[self.zipped.get('time', slice(0, 0))]
                if ddmmyy and HHMM:
                    timestamp = datetime.strptime(ddmmyy + HHMM + "59", ft)
                else:
                    timestamp = None
                yield record, timestamp
            fd.close()
        raise StopIteration

    def mstreader(self, mstfiles, stdout=False):
        cdr_msg_identifier = "CDR <--"
        ft = "%m/%d/%y%H:%M:%S"
        for mstfile in mstfiles:
            if stdout:
                sys.stdout.write("Processing: %s\r" % mstfile)
                sys.stdout.flush()
            try:
                fd = open(mstfile)
            except:
                continue
            try:
                mmddyy = next(dropwhile(lambda x: not
                     re.search(r"\s+(\d{2}/\d{2}/\d{2})\s*$", x), fd)).strip()
            except:
                fd.close()
                continue
            partial = False
            buff = []
            for line in fd:
                if partial:
                    line = line.strip()
                    if line:
                        buff.append(line[2:])
                        if len(buff) == 2:
                            record = "".join(buff)
                            record = record.replace("<CR>", "\r")
                            record = record.replace("<LF>", "\n")
                            if len(record) < self.length:
                                continue
                            yield record.replace("'", " "), timestamp
                            partial = False
                elif cdr_msg_identifier in line:
                    del buff[:]
                    l = line.split()
                    timestamp = datetime.strptime(mmddyy + l[1][0:8], ft)
                    partial = True
            fd.close()
        raise StopIteration

    def ecsreader(self, ecsfiles, stdout=False):
        cdr_msg_identifier = "  36 04"
        ft = "%Y%m%d:%H%M%S"
        for ecsfile in ecsfiles:
            if stdout:
                sys.stdout.write("Processing: %s\r" % ecsfile)
                sys.stdout.flush()
            try:
                fd = open(ecsfile)
            except:
                continue
            for line in fd:
                if cdr_msg_identifier in line:
                    timestamp = datetime.strptime(line[0:15], ft)
                    line = line.split("MST", 1)[1][:-2].lstrip()
                    _, payload = line.split("  ", 1)
                    record = unhexlify(payload.replace(" ", "")[8:])
                    if len(record) < self.length:
                        continue
                    yield record, timestamp
            fd.close()
        raise StopIteration


class CDRDictReader(CDRReader):
    """
    Subclass of CDRReader which returns the CDR record items
    in a dictionary except the "space" items.
    Output: the cdr record as dict

    Usage example:
    
    from glob import glob
    reader = CDRDictReader(format=FORMAT, ecsfiles=glob("./2*.log"))
    for record in reader:
        print record['date'], record['calling-num'], reader.timestamp
    """
    def __init__(self, *args, **kwargs):
        super(CDRDictReader, self).__init__(*args, **kwargs)

    def __next__(self):
        record = super(CDRDictReader, self).__next__()
        return dict((k,record[v]) for k,v in
                     self.zipped.iteritems() if k != "space")

    def next(self):
        return self.__next__()


if __name__ == "__main__":
    if len(sys.argv[1:]) == 0:
        raise TypeError("Need inputfile list (0 given)")
    if sys.argv[1].startswith("20"):
        reader = CDRReader(format=FORMAT, ecsfiles=sys.argv[1:])
    elif sys.argv[1].endswith(".m"):
        reader = CDRReader(format=FORMAT, mstfiles=sys.argv[1:])
    else:
        reader = CDRReader(format=FORMAT, txtfiles=sys.argv[1:])
    try:
        for record in reader:
            print reader.timestamp, repr(record)
    except:
        sys.stderr.close()
        sys.exit(1)


