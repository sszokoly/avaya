#!/usr/bin/env python
'''
#############################################################################
## Name: serial_asai
## Description: summarizes calls based on ASAI/CTI messages from MST files 
## Options: see help, -h
## Date: 2019-02-04
## Author: szokoly@avaya.com
#############################################################################
'''
import os
os.nice(19)
import sys
from itertools import izip
from optparse import OptionParser, SUPPRESS_HELP
from binascii import unhexlify
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

if not hasattr(__builtins__, "any"):
    def any(iterable):
        for element in iterable:
            if element:
                return True
        return False


LENGHTS = {
            "timestamp" : 12,
            "calling"   : 21,
            "called"    : 21,
            "callids"   : 9,
            "connected" : 24,
            "crv"       : 4,
            "link"      : 4,
            "trunks"    : 15,
            "event"     : 36,
            "ucid"      : 20,
            "uui"       : 64,
        }

DEFAULT_FIELDS = [
                  "timestamp", 
                  "link", 
                  "callids", 
                  "calling", 
                  "called",
                  "connected", 
                  "trunks", 
                  "event"
                  ]

class ASAICall(object):
    def __init__(self, callid):
        self.callid = callid
        self.calling = []
        self.called = []
        self.connected = []
        self.event = []
        self.link = []
        self.timestamp = []
        self.trunks = []
        self.ucid = []
        self.ucid_unique = []
        self.uui = []
    def update(self, msg):
        ucid = msg.ucid
        if ucid and ucid not in self.ucid_unique:
            self.ucid_unique.append(ucid)
        self.ucid.append(ucid)
        self.timestamp.append(msg.timestamp)
        self.link.append(msg.link)
        self.calling.append(msg.calling)
        self.called.append(msg.called)
        self.connected.append(" ".join(msg.connected))
        self.trunks.append(" ".join(msg.trunks))
        self.event.append(msg.event)
        self.uui.append(msg.uui)
    def __str__(self):
        out = ["\n"]
        out.append("Callid: 0x%s  UCID (%s): %s" % (
                                          self.callid, 
                                          len(self.ucid_unique), 
                                          ' '.join(self.ucid_unique)))
        out.append("%s %s %s %s %s %s %s %s" % (
                                          "Timestamp".rjust(12),
                                          "Link".rjust(4),
                                          "Calling".rjust(15),
                                          "Called".rjust(15),
                                          "Connected".rjust(24),
                                          "Trunks".rjust(7),
                                          "UCID".rjust(40),
                                          "Event".ljust(20)))
        for timestamp, link, calling, called, connected, trunks, ucid, event in izip(
                                          self.timestamp,
                                          self.link,
                                          self.calling,
                                          self.called,
                                          self.connected,
                                          self.trunks,
                                          self.ucid,
                                          self.event):
            out.append("%s %s %s %s %s %s %s %s" % (
                                          timestamp.rjust(12),
                                          link.rjust(4),
                                          calling.rjust(15),
                                          called.rjust(15),
                                          connected.rjust(24),
                                          trunks.rjust(7),
                                          ucid.rjust(40),
                                          event.ljust(20)))
        return "\n".join(out)


class ASAIMsg(object):
    def __init__(self, msg):
        self._str = msg
    @property
    def crv(self):
        start = self._str.find("crv")
        if start < 0:
            return ""
        start_crv = self._str.find("_", start+4) + 1
        return self._str[start_crv:start_crv + 4]
    @property
    def link(self):
        start = self._str.find("CTI Link number")
        if start < 0:
            return ""
        start_link = self._str.find(" ", start+16)
        end_link = self._str.find("\n", start_link)
        if end_link < 0:
            end_link = None
        return str(int(self._str[start_link:end_link].strip()))
    @property
    def timestamp(self):
        start = self._str.find(" ", 0)
        if start < 0:
            return ""
        start_time = start+2
        end_time = self._str.find(" ", start_time)
        if end_time < 0:
            end_time = None
        return self._str[start_time:end_time]
    @property
    def type(self):
        start = self._str.find("ASAI association type")
        if start < 0:
            return ""
        start_type = self._str.find(" ", start+22)
        end_type = self._str.find("\n", start_type)
        if end_type < 0:
            end_type = None
        return self._str[start_type:end_type].strip()


class ASAIDomainMsg(ASAIMsg):
    def __init__(self, msg, ucid_dec=True, uui_ascii=True):
        super(ASAIDomainMsg, self).__init__(msg)
        self.ucid_dec = ucid_dec
        self.uui_ascii = uui_ascii
    @property
    def calling(self):
        start = self._str.find("CALLING PARTY NUMBER")
        if start < 0:
            return ""
        start_num = self._str.find(" ", start+21) + 1
        end_num = self._str.find("\n", start_num)
        if end_num < 0:
            end_num = None
        return self._str[start_num:end_num]
    @property
    def called(self):
        start = self._str.find("CALLED PARTY NUMBER")
        if start < 0:
            return ""
        start_num = self._str.find(" ", start+20) + 1
        end_num = self._str.find("\n", start_num)
        if end_num < 0:
            end_num = None
        return self._str[start_num:end_num]
    @property
    def callids(self):
        start = self._str.find("CALL IDENTITY")
        if start < 0:
            return []
        ids = []
        while start != -1: 
            start_callid = self._str.find(" ", start+13) + 1
            end_callid = self._str.find("  ", start_callid)
            if end_callid < 0:
                end_callid = None
            ids.append(self._str[start_callid:end_callid].replace(" ",""))
            start = self._str.find("CALL IDENTITY", start+1)
        return ids
    @property
    def connected(self):
        start = self._str.find("CONNECTED NUMBER")
        if start < 0:
            return []
        nums = []
        while start != -1:
            start_num = self._str.find(" ", start+17) + 1
            end_num = self._str.find("\n", start_num)
            if end_num < 0:
                end_num = None
            nums.append(self._str[start_num:end_num])
            start = self._str.find("CONNECTED NUMBER", start+1)
        return nums
    @property
    def event(self):
        start = self._str.find("SPECIFIC EVENT")
        if start < 0:
            return ""
        start_event = self._str.find(" ", start+17)
        end_event = self._str.find("\n", start_event)
        if end_event < 0:
            end_event = None
        return self._str[start_event:end_event].strip()
    @property
    def trunks(self):
        start = self._str.find("SNC grp")
        if start < 0:
            return []
        trks = []
        while start != -1:
            start_trk = self._str.find(" ", start+7) + 1
            end_trk = self._str.find("\n", start_trk)
            if end_trk < 0:
                end_trk = None
            trks.append(self._str[start_trk:end_trk].replace(" trk ", "/"))
            start = self._str.find("SNC grp", start+1)
        return trks
    @property
    def ucid(self):
        start = self._str.find("UNIVERSAL CALL ID")
        if start < 0:
            return ""
        start_ucid = self._str.find(" ", start+17) + 1
        end_ucid = self._str.find("  ", start_ucid)
        if end_ucid < 0:
            end_ucid = None
        ucid = self._str[start_ucid:end_ucid].replace(" ", "")
        if self.ucid_dec:
            return self.ucid_to_dec(ucid)
        return ucid
    @property
    def uui(self):
        start = self._str.find("user-specific protocol")
        if start < 0:
            return ""
        start_uui = self._str.find("|", start+32) + 3
        end_uui = self._str.find("<-", start_uui)
        if end_uui < 0:
            end_uui = None
        uui = self._str[start_uui:end_uui]
        uui = "".join(x for x in uui.split() if x != "|")
        if self.uui_ascii:
            return self.uui_to_ascii(uui)
        return uui
    @staticmethod
    def ucid_to_dec(ucid):
        if ucid:
            try:
                if "x" in ucid:
                    _, ucid = ucid.split("x")
                g1 = str(int(ucid[:4], 16)).zfill(5)
                g2 = str(int(ucid[4:8], 16)).zfill(5)
                g3 = str(int(ucid[8:], 16))
                return "".join((g1, g2, g3))
            except:
                return "<ucid_to_dec failed>"
        return ""
    @staticmethod
    def uui_to_ascii(uui):
        if uui:
            try:
                return unhexlify(uui)
            except:
                return "<uui_to_ascii failed>"
        return ""

def ucid_hex_to_dec(ucid):
    if ucid:
        try:
            if "x" in ucid:
                _, ucid = ucid.split("x")
            g1 = str(int(ucid[:4], 16)).zfill(5)
            g2 = str(int(ucid[4:8], 16)).zfill(5)
            g3 = str(int(ucid[8:], 16))
            return "".join((g1, g2, g3))
        except:
            return "<ucid_hex_to_dec failed>"
    return ""

def ucid_dec_to_hex(ucid):
    if ucid:
        try:
            g1 = hex(int(ucid[:5]))[2:].zfill(4)
            g2 = hex(int(ucid[5:10]))[2:].zfill(4)
            g3 = hex(int(ucid[10:]))[2:]
            return "".join((g1, g2, g3))
        except:
            return "<ucid_dec_to_hex failed>"
    return ""

def asai_domain_mst_reader(mstfiles, stdout=None):
    domain_msg_identifier = "<-- DOMAIN"
    if isinstance(mstfiles, str):
        mstfiles = [mstfiles]
    for mstfile in mstfiles:
        if stdout:
            sys.stdout.write("Processing: %s\r" % mstfile)
            sys.stdout.flush()
        try:
            fd = open(mstfile)
        except:
            continue
        partial = False
        buff = []
        for line in fd:
            if partial:
                line = line.strip()
                if line:
                    buff.append(line)
                else:
                    yield "\n".join(buff)
                    partial = False
            elif domain_msg_identifier in line:
                del buff[:]
                buff.append(line.strip())
                partial = True
        fd.close()
    raise StopIteration

def get_calls(mstfiles):
    asai_calls = OrderedDict()
    reader = asai_domain_mst_reader(mstfiles)
    for asai_domain_msg in reader:
        msg = ASAIDomainMsg(asai_domain_msg)
        for callid in msg.callids:
            if callid:
                asai_calls.setdefault(callid, ASAICall(callid)).update(msg)
    return asai_calls 

def main():
    parser = OptionParser(usage='%prog [<options>] <decoded MST file(s)>',
            description="Serializes outbound ASAI DOMAIN messages from MST traces.")
    parser.add_option('-c', '--callid',
            action='store',
            default=False,
            dest='filter_callid',
            metavar=' ',
            help='CallID filter, separated by |')
    parser.add_option('-l', '--link',
            action='store',
            default=False,
            dest='filter_link',
            metavar=' ',
            help='ASAI link filter, separated by |')
    parser.add_option('-n', '--number',
            action='store',
            default=False,
            dest='filter_num',
            metavar=' ',
            help='Calling/Called/Connected filter, separated by |')
    parser.add_option('-t', '--trunks',
            action='store',
            default=False,
            dest='filter_trk',
            metavar=' ',
            help='Trunk/channel filter, separated by |')
    parser.add_option('-u', '--ucid',
            action='store',
            default=False,
            dest='filter_ucid',
            metavar=' ',
            help='UCID filter, UCIDs (hex or dec) separated by |')
    parser.add_option('-f', '--fields',
            action='store',
            default=False,
            dest='fields',
            metavar=' ',
            help='fields to display.                         \
                  Available:                                 \
                    timestamp,crv,link,callids,calling,called,connected,\
                    trunks,ucid,uui,event                           \
                  Default:                                   \
                    timestamp,link,callids,calling,called,connected,trunks,\
                    event                                    \
                    fields must be separated by |')
    parser.add_option('-e', '--expert',
            action='store_true',
            default=False,
            dest='expert',
            metavar=' ',
            help=SUPPRESS_HELP)
    opts, args = parser.parse_args()
    if not args:
        print "Need an MST input file (0 given), existing!"
        return 1
    else:
        mstfiles = args
    if opts.fields:
        fields = [x for x in opts.fields.split("|") if x in LENGHTS]
    else:
        fields = DEFAULT_FIELDS
    if opts.filter_callid:
        filter_callid = set(opts.filter_callid.split("|"))
    else:
        filter_callid = None
    if opts.filter_num:
        filter_num = set(opts.filter_num.split("|"))
    else:
        filter_num = None
    if opts.filter_trk:
        filter_trk = set(opts.filter_trk.split("|"))
    else:
        filter_trk = None
    if opts.filter_ucid:
        filter_ucid = []
        for filter in opts.filter_ucid.split("|"):
            if len(filter) < 20:
                filter = ucid_hex_to_dec(filter)
            filter_ucid.append(filter)
        filter_ucid = set(filter_ucid)
    else:
        filter_ucid = None
    if opts.filter_link:
        filter_link = set(opts.filter_link.split("|"))
    else:
        filter_link = None
    if not opts.expert:
        reader = asai_domain_mst_reader(mstfiles)
        out = []
        for field in fields:
            out.append(field.title().rjust(LENGHTS[field]))
        print " ".join(out)
        for asai_domain_msg in reader:
            msg = ASAIDomainMsg(asai_domain_msg)
            if filter_link and msg.link not in filter_link:
                continue
            if filter_callid and not filter_callid & set(msg.callids):
                continue
            elif filter_num and not filter_num & set([msg.calling,
                                                      msg.called] +
                                                   msg.connected):
                continue
            elif filter_trk and not filter_trk & set(msg.trunks):
                continue
            elif filter_ucid and msg.ucid not in filter_ucid:
                continue
            del out[:]
            for field in fields:
                value = getattr(msg, field)
                if isinstance(value, list):
                    value = " ".join(value)
                out.append(value.rjust(LENGHTS[field]))
            print " ".join(out)
    else:
        calls = get_calls(mstfiles)
        ucids = {}
        for call in calls.itervalues():
            for ucid, calling, uui in izip(call.ucid, call.calling, call.uui):
                if ucid and calling and len(calling) > 8:
                    ucids.setdefault(ucid, set()).add(calling)
        for key in sorted(ucids):
            if len(ucids[key]) >= 2:
                print "UCID: %s  Calling: %s" % (key.rjust(20), ' '.join(
                        sorted(list(ucids[key]), key=len)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
