#!/usr/bin/env python
import re
import string
import sys
from binascii import unhexlify
from datetime import datetime
from itertools import dropwhile

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
