#!/usr/bin/env python
'''
#############################################################################
## Name: counter
## Description: this utility counts string patterns from log files or from
##              the stdin on a per interval basis, the patterns and intervals
##              can be user defined or taken form the list of predefined ones.
## Options: see help, -h
## Version: see option -v
## Date: 2018-08-24
## Author: szokoly@avaya.com
#############################################################################
'''
import fileinput
import os
try:
    os.nice(19)
except:
    pass
import re
import sys
import time
from copy import deepcopy
from glob import glob
from heapq import nlargest
from operator import itemgetter
from optparse import Option, OptionGroup, OptionParser, OptionValueError
from optparse import SUPPRESS_HELP
try:
    from collections import Counter
except ImportError:
    from heapq import nlargest
    class Counter(object):
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
            if not isinstance(other, bag):
                return False
            return self._data == other._data
        def __ne__(self, other):
            if not isinstance(other, bag):
                return True
            return self._data != other._data
        def __hash__(self):
            raise TypeError
        def __repr__(self):
            return 'Counter(%r)' % self._data
        def copy(self):
            return self.__class__(self)
        __copy__ = copy # For the copy module
        def __deepcopy__(self, memo):
            from copy import deepcopy
            result = self.__class__()
            memo[id(self)] = result
            data = result._data
            result._data = deepcopy(self._data, memo)
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
        def iteritems(self):
            return self._data.iteritems()
        def keys(self):
            return self._data.keys()            
        def most_common(self, n=None):
            if n is None:
                return sorted(self.itercounts(), key=itemgetter(1),
                                                     reverse=True)
            it = enumerate(self.itercounts())
            nl = nlargest(n, ((cnt, i, elem) for (i, (elem, cnt)) in it))
            return [(elem, cnt) for cnt, i, elem in nl]


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

class LimitedSizeDict(OrderedDict):
  def __init__(self, *args, **kwds):
    self.size = kwds.pop("size", None)
    OrderedDict.__init__(self, *args, **kwds)
    self._check_size()

  def __setitem__(self, key, value):
    OrderedDict.__setitem__(self, key, value)
    self._check_size()

  def _check_size(self):
    if self.size is not None:
      while len(self) > self.size:
        self.popitem(last=False)


class MultipleOption(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)


#Python 2.4 does not have all()
if not hasattr(__builtins__, 'all'):
    def all(iterable):
        for element in iterable:
            if not element:
                return False
        return True

DESCRIPTION = '''
This utility counts patterns in log files or in the lines received from stdin
on a per interval basis. The patterns and intervals are user defined but both
can used predefined defaults. By default the last 7 intervals are printed out.
The interval is based on the slice of the timestamp, for example for a line
starting with a timestamp in "yyyymmdd:HHMMSS...." format using only the first
11 characters, "yyyymmdd:HH", the intervall will be one HOUR. The pattern is
a combination of a keyword, "event", and any accompaning string qualifiers.
For example "DENYEVT,(event=\d+) (d1=\S+) (d2=\S+).*]" specifies DENYEVT as
event type and a group of potentially three components defined by a regular
expression. If input files are not provided the input is read from stdin.'''

PATTERNS = {
    'alarm' : {'MTCEVT ALM' : '(type=\S+) (lname=\S+) (pname=\S+) (cbusy=\S+) (filt=\S+).*]'},
    'error' : {'MTCEVT ERR' : '(type=\S+) (lname=\S+) (pn1=\S+) (pn2=\S+) (aux=\S+).*]'},
    'denial' : {'DENYEVT' : '(event=\d+) (d1=\S+) (d2=\S+).*]'},
    'proc_err' : { 'proc_err:' : '(pro=\d+).*(seq=\d+),(da1=\S+),(da2=\S+).*]'},
	}
TIMESTAMP_POSITIONS = {
    'S' : (0, 15),
    'SEC' : (0, 15),
    'TS' : (0, 14),
    'TSEC' : (0, 14),
    'TENSEC' : (0, 14),
    'M' : (0, 13),
    'MIN' : (0, 13),
    'T' : (0, 12),
    'TMIN' : (0, 12),
    'TENMIN' : (0, 12),
    'H' : (0, 11),
    'HOUR' : (0, 11),
    'D' : (0, 8),
    'DAY' : (0, 8),
    }
DEFAULT_TIMEPOS = TIMESTAMP_POSITIONS["HOUR"]
DEFAULT_PATTERN = PATTERNS["denial"]
VERSION = 0.1


def pprint_intervals(i, name="", ordered=True, column_gap=2, print_zero=False):
    col_names = i.keys()
    if ordered:
        col_names.sort()
    row_names = sorted(list(set(c for v in i.values() for c in v)))
    if ordered:
        row_names.sort()
    name_width = len(name)
    row_name_width = max(len(x) for x in row_names) + column_gap
    col_name_width = max(len(x) for x in col_names) + column_gap
    cell_width = max(len(str(i[k][c])) for k,v in i.iteritems() for c in v)
    left_pane_width = max(name_width, row_name_width)
    col_width = max(col_name_width, cell_width)
    output = []
    output.append(''.join((name.ljust(left_pane_width),
                           ''.join(x.rjust(col_width) for x in col_names))))
    for row_name in row_names:
        cells = [str(i[col_name][row_name]) for col_name in col_names]
        if not print_zero:
            #this doesn't work in Python 2.4
            #cells = [cell if int(cell) else " " for cell in cells]
            c = []
            for cell in cells:
                if int(cell):
                    c.append(cell)
                else:
                    c.append(" ")
            cells = c
        output.append(''.join((row_name.ljust(left_pane_width),
                               ''.join(x.rjust(col_width) for x in cells))))
    return "\n".join(output)

def iterevents(patterns, logfiles, timepos=(0,11)):
    timepos_slice = slice(*timepos)
    for line in fileinput.input(logfiles, bufsize=2048*2048):
        events = [pattern for pattern in patterns if pattern in line]
        if events:
            m = re.search(patterns[events[0]], line)
            if not m:
                continue
            yield line[timepos_slice], events[0], m.groups()

def parse_ranges(ranges):
    l = []
    for range in sorted(ranges):
        if '-' in range:
            start, end = range.split('-')
        else:
            start, end = range, range
        if end < start:
            start, end = end, start
        if (all(re.search(r"\d{4}(:\d{1,6})?$", x) for x in (start,end)) and
                                                    len(start) == len(end)):
            l.append((start, end))
    return l

def parse_patterns(patterns):
    d = {}
    for pattern in patterns:
        try:
            event, regex = pattern.split(',')
        except ValueError:
            continue
        d[event] = regex
    return d

def parse_args(args):
    parser = OptionParser(
        option_class=MultipleOption,
        usage="%prog [<options>] [logfiles|stdin]",
        description=DESCRIPTION,
        version='%%prog v%s' % VERSION)
    parser.add_option("-?", "--?",
        action="store_true",
        dest="HELP",
        default=False,
        help=SUPPRESS_HELP)
    parser.add_option("-i", "--timepos",
        action="store",
        dest="timepos",
        metavar=" ",
        help='specifies the position of the timestamp in the\
 input line. If the input line starts with a\
 yyyymmdd:HHMMSS formatted timestamp then the following builtin intervals can\
 be used: SEC, TENSEC, MIN, TENMIN, HOUR (default) or DAY. For other \
 timestamp formats define the first and last character position of the\
 desired timestamp slice separeted by coma. For example:  "--timepos=0,11" or\
 "--timepos=DAY" or "-i TENMIN"')
    parser.add_option("-p",
        action="extend",
        type="string",
        dest="patterns",
        metavar="event,regex",
        help='pattern to look for and count in the input line, comprised of an\
 <event> type, a keyword which the inputline must contain, for example DENYEVT,\
 and a <regex> pattern capturing the desired qualifiers, the occurrences of\
 which are to be counted. For instance to count only the DENYEVT event types\
 regardless of their d1 and d2 values: -p "DENYEVT,(event=\d+).*]" if the\
 input line is "bla bla bla DENYEVT ERR event=2176 d1=71f2 d2=126.28.8.17]"')
    parser.add_option("-n",
        action="store",
        default=7,
        dest="buffsize",
        metavar="<number>",
        type="int",
        help="number of intervals to print, the default is 7")
    parser.add_option("-v",
        action="count",
        default=1,
        dest="verbosity",
        metavar=" ",
        help="add one or more to print one or more groups of the regular\
 expression groups defined by -p")
    parser.add_option("-z",
        action="store_true",
        default=False,
        dest="print_zero",
        help="print 0 instead of empty field in the output report")

    group = OptionGroup(parser,
 "Convenience options for Avaya Communication Manager")
    group.add_option("--ecs",
        action="store",
        dest="ecs",
        metavar=" ",
        help='predefined patterns for Avaya CM events in ecs logs. Choices\
 are: [alarm, error, denial, proc_err] separated by only coma. For example:\
 "--ecs denial,proc_err". If no other pattern (-p or --ecs) is specified the\
 "--ecs denial" is used by default')
    group.add_option('-t',
        action="extend",
        type="string",
        dest="custom_ranges",
        metavar="TIME",
        help="filter for a particular date/time range                         \
        -time pattern                                                         \
        yyyy[mm[dd:[HH[MM[SS[mmm]]]]]]                                        \
        -time range                                                           \
        yyyy[mm[dd:[HH[MM[SS[mmm]]]]]]-yyyy[mm[dd:[HH[MM[SS[mmm]]]]]]")
    parser.add_option_group(group)
    options, arguments = parser.parse_args()

    if options.HELP:
        parser.print_help()
        sys.exit()

    args = {}
    args["verbosity"] = options.verbosity
    args["buffsize"] = options.buffsize
    args["print_zero"] = options.print_zero
    args["patterns"] = OrderedDict()
    args["logfiles"] = []
    args["custom_ranges"] = None
    args["timepos"] = DEFAULT_TIMEPOS

    if options.patterns:
        args["patterns"].update(parse_patterns(options.patterns))

    if options.ecs:
        for item in options.ecs.split(","):
            if item.strip() in PATTERNS:
                args["patterns"].update(PATTERNS[item.strip()])
    if not args["patterns"]:
        args["patterns"] = DEFAULT_PATTERN

    if options.timepos:
        if options.timepos not in TIMESTAMP_POSITIONS:
            first, last = options.timepos.split(',')
            args["timepos"] = (int(first), int(last))
        else:
            args["timepos"] = TIMESTAMP_POSITIONS[options.timepos]

    if options.custom_ranges:
        #this doesnt work in Python 2.4
        #custom_ranges = [(s,e) if e else (s,s) for s,_,e in
                 #(t.partition('-') for t in sorted(options.custom_ranges))]
        args["custom_ranges"] = parse_ranges(options.custom_ranges)
        if args["custom_ranges"]:
            args["timepos"] = (0, len(args["custom_ranges"][0][0]))

    if arguments:
        logs = []
        for argument in arguments:
            logs.extend(glob(argument))
        logfiles = sorted(log for log in logs if os.path.isfile(log))
        if not logfiles:
            print "No valid log files found in the provided arguments!"
            sys.exit(1)
        args["logfiles"] = logfiles
    return args

def main(args):
    args = parse_args(args)
    events = iterevents(args["patterns"], args["logfiles"], args["timepos"])
    custom_ranges = args["custom_ranges"]
    intervals = OrderedDict()

    #Main event loop
    for item in events:
        ts, event, qualifiers = item
        if custom_ranges:
            start_end = [(s,e) for s,e in custom_ranges if s<=ts[0:len(s)]<=e]
            if start_end:
                ts = '-'.join(start_end[0])
            else:
                continue 
        intervals.setdefault(event, LimitedSizeDict(size=args["buffsize"])
                ).setdefault(ts, Counter()
                ).update([' '.join(qualifiers[:args["verbosity"]])])
    for event in intervals:
        print pprint_intervals(intervals[event], name=event,
                               print_zero=args["print_zero"]), "\n"

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(1)
