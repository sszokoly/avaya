# -*- coding: utf-8 -*-
"""Avaya SBCE utilities."""
from __future__ import print_function
import bz2
import gzip
import os
import re
import shlex
import time
from collections import namedtuple
from datetime import datetime
from glob import glob
from itertools import chain
from netifaces import interfaces, ifaddresses, AF_INET
from platform import node
from subprocess import Popen, PIPE
from textwrap import wrap

Server = namedtuple("Server", ["name", "type"])

def memoize(func):
    """A decorator to cache the return value of func.

    Args:
        func: function to decorate

    Returns:
        wrapper: decorated function
    """
    cache = {}

    def wrapper(args):
        try:
            return cache[args]
        except KeyError:
            cache[args] = func(args)
            return cache[args]
    return wrapper


class Flow(object):
    """Data structure to store flow counters."""
    __slots__ = [
        "InIf", "InSrcIP", "InSrcPort", "InDstIP", "InDstPort", "OutIf",
        "OutSrcIP", "OutSrcPort", "OutDstIP", "OutDstPort", "InVlan",
        "OutVlan", "Enc", "Dec", "Snt", "Drp", "Rx", "Rly", "Ech"
    ]

    def __init__(self, InIf, InSrcIP, InSrcPort, InDstIP, InDstPort, OutIf,
                 OutSrcIP, OutSrcPort, OutDstIP, OutDstPort, InVlan, OutVlan,
                 Enc, Dec, Snt, Drp, Rx, Rly, Ech):
        self.InIf = InIf
        self.InSrcIP = InSrcIP
        self.InSrcPort = InSrcPort
        self.InDstIP = InDstIP
        self.InDstPort = InDstPort
        self.OutIf = OutIf
        self.OutSrcIP = OutSrcIP
        self.OutSrcPort = OutSrcPort
        self.OutDstIP = OutDstIP
        self.OutDstPort = OutDstPort
        self.InVlan = InVlan
        self.OutVlan = OutVlan
        self.Enc = Enc
        self.Dec = Dec
        self.Snt = Snt
        self.Drp = Drp
        self.Rx = Rx
        self.Rly = Rly
        self.Ech = Ech

    def __lt__(self, other):
        return self.InIf < other.InIf

    def __gt__(self, other):
        return self.InIf > other.InIf

    def _asdict(self):
        return {slot: getattr(self, slot, None) for slot in self.__slots__}

    def __repr__(self):
        return "Flow({0})".format(
            ", ".join(repr(getattr(self, k)) for k in self.__slots__)
        )


class Msg(object):
    """Data structure to store trace log message info."""
    __slots__ = ["srcip", "srcport", "dstip", "dstport", "timestamp",
                 "direction", "body", "proto", "method"]

    def __init__(self, srcip="", srcport=None, dstip="", dstport=None,
                 timestamp=None, direction="", body="", proto="", method=""):
        self.srcip = srcip
        self.srcport = srcport
        self.dstip = dstip
        self.dstport = dstport
        self.timestamp = timestamp
        self.direction = direction
        self.body = body
        self.proto = proto
        self.method = method

    def __str__(self):
        return str({k: getattr(self, k) for k in self.__slots__})


class SsyndiSIPReader(object):
    """Generator class which parses SSYNDI log files, extracts CALL CONTROL
    type SIP messages and yields Msg class instance.
    """
    LOGDIR = "/usr/local/ipcs/log/ss/logfiles/elog/SSYNDI"
    SSYNDI_GLOB = "SSYNDI_*_ELOG_*"

    def __init__(self, logfiles=None, logdir=None, methods=None,
                 ignore_fnu=False):
        """Initializes a SsyndiSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of SSYNDI log files
                to parse, if not provided it starts reading the latest SSYNDI
                log in LOGDIR and keep doing it so when the log file rotates
            logdir (str): path to directory if SSYNDI logs are not under the
                default LOGDIR folder
            methods (list): list of methods to capture
            ignore_fnu (bool): to ignore "off-hook" "ec500" fnu requests

        Returns:
            gen (SsyndiSIPReader): a SsyndiSIPReader generator

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.ssyndi_glob = os.path.join(self.logdir, self.SSYNDI_GLOB)
        self.methods = set(methods) if methods else None
        self.ignore_fnu = ignore_fnu

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
            self.filename = self.last_ssyndi()
            self.fd = open(self.filename)
            self.fd.seek(0, 2)

    def __next__(self):
        """Generator"""
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
                elif (
                        os.stat(self.filename).st_size < 10482000 or
                        self.filename == self.last_ssyndi()
                ):
                    return None
                else:
                    self.fd.close()
                    self.filename = self.last_ssyndi()
                self.fd = open(self.filename)
                readaline = self.fd.readline
            elif "SIP MSG AT CALL CONTROL" in line:
                lines = [line]
                while not lines[-1].startswith("IP:"):
                    lines.append(readaline())

                if self.methods and self._method(lines) not in self.methods:
                    continue
                if self.ignore_fnu and self._is_fnu(lines[1]):
                    continue

                msg = Msg(**self.splitaddr(lines[-1]))
                msg.timestamp = self.strptime(lines[0][1:27])
                msg.direction = lines[0][-5:-2].lstrip()
                msg.body = "".join(lines[1:-1])
                msg.proto = self.get_proto(msg.body)
                msg.method = self._method(lines)
                return msg

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_ssyndi(self):
        """str: Returns the last SSYNDI log file by file name."""
        return max(x for x in glob(self.ssyndi_glob))

    @property
    def progress(self):
        """int: Returns the percentage of processed input logfiles."""
        if self.total_logfiles > 0:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses address line which contains the source and destination
        host IP address and transport protocol port numbers. To speed up
        processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"srcip": <str srcip>, "srcport": <str srcport>,
                   "dstip": <str dstip>, "dstport": <str dstport>}
        """
        p = r"IP:(?P<srcip>[a-fx0-9.]*):(?P<srcport>\d+) --> (?P<dstip>[a-fx0-9.]*):(?P<dstport>\d+)"

        try:
            d = re.search(p, line).groupdict()
        except:
            return {"srcip": "", "srcport": None, "dstip": "", "dstport": None}

        if "x" in line:
            d["srcip"] = ".".join(str(int(x, 16)) for x in
                                  wrap(d["srcip"][2:].zfill(8), 2))
            d["dstip"] = ".".join(str(int(x, 16)) for x in
                                  wrap(d["dstip"][2:].zfill(8), 2))
        d["srcport"] = int(d["srcport"])
        d["dstport"] = int(d["dstport"])
        return d

    @staticmethod
    def get_proto(body):
        """Extracts protocol type from the top most Via header.

        Args:
            body (str): SIP message body

        Returns:
            str: Transport protocol type (UDP, TCP or TLS)
        """
        start = body.find("Via:")
        if start == -1:
            start = body.find("v:")
            if start == -1:
                return "UDP"
            else:
                start += 11
        else:
            start += 13
        return body[start:start+3].upper()

    @staticmethod
    def _method(lines):
        """Returns SIP message method from CSeq line.

        Args:
            lines (list): list of SIP message lines

        Returns:
            str: SIP method or empty str
        """
        try:
            hdr = next(x for x in lines if x.startswith("CSeq"))
            if hdr:
                params = hdr.split()
                if len(params) == 3:
                    return params[2]
            return ""
        except StopIteration:
            return ""

    @staticmethod
    def _is_fnu(line):
        """Returns True if line contains FNU.

        Args:
            line (str): SIP Request URI line

        Returns:
            bool: True if line contians off-hook or ec500 FNU 
        """
        return ("avaya-cm-fnu=off-hook" in line or
                "avaya-cm-fnu=ec500" in line)

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime

        Args:
            s (str): SSYNDI timestamp

        Returns:
            datetime obj: datetime object
        """
        return datetime(
            int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
            int(s[14:16]), int(s[17:19]), int(s[20:26])
        )


class TracesbcSIPReader(object):
    """Generator class which parses tracesbc_sip log files, extracts
    message details and yields Msg class instance.
    """
    LOGDIR = "/archive/log/tracesbc/tracesbc_sip"
    TRACESBCSIP_GLOB = "tracesbc_sip_[1-9][0-9][0-9]*[!_][!_]"

    def __init__(self, logfiles=None, logdir=None, methods=None,
                 ignore_fnu=False):
        """Initializes a TracesbcSIPReader instance.

        Args:
            logfiles (list(str), optional): a collection of tracesbc_sip
                log files to parse, if not provided it starts reading the
                latest tracesbc_sip log in LOGDIR and keep doing it so
                when the log file rotates
            logdir (str): path to directory if tracesbc_sip logs are not
                under the default LOGDIR folder
            methods (list): list of methods to capture
            ignore_fnu (bool): to ignore "off-hook" "ec500" fnu requests

        Returns:
            gen (TracesbcSIPReader): a TracesbcSIPReader generator

        Raises:
            StopIteration: when logfiles is not None and reached the end
                of the last logfile
        """
        self.logdir = logdir or self.LOGDIR
        self.tracesbc_glob = os.path.join(self.logdir, self.TRACESBCSIP_GLOB)
        self.methods = set(methods) if methods else None
        self.ignore_fnu = ignore_fnu

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
            if not self._is_last_tracesbc_gzipped():
                self.fd = self.zopen(self.filename)
                self.fd.seek(0, 2)

    def __next__(self):
        if self.fd is None:
            if self._is_last_tracesbc_gzipped():
                return None
            self.fd = self.zopen(self.filename)
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
                    if self._is_last_tracesbc_gzipped():
                        return None
                else:
                    return None
                self.fd = self.zopen(self.filename)
                readaline = self.fd.readline
            elif line.startswith("["):
                lines = [line]
                while not lines[-1].startswith("--"):
                    lines.append(readaline().lstrip("\r\n"))

                if self.methods and self._method(lines[2:]) not in self.methods:
                    continue
                if self.ignore_fnu and self._is_fnu(lines[2]):
                    continue

                msg = Msg(**self.splitaddr(lines[1]))
                msg.timestamp = self.strptime(lines[0][1:-3])
                msg.body = "".join(x for x in lines[2:-1] if x)
                msg.method = self._method(lines)
                return msg

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def last_tracesbc_sip(self):
        """str: Returns the last tracesbc_sip log file."""
        return max(glob(self.tracesbc_glob))

    def _is_last_tracesbc_gzipped(self):
        """bool: Return True if last tracesbce_sip is gzipped."""
        self.filename = self.last_tracesbc_sip()
        if self.filename.endswith(".gz"):
            self.fd = None
            return True
        return False

    @property
    def progress(self):
        """int: Returns the percentage of processed logfiles."""
        if self.total_logfiles:
            return int(100-(len(self.logfiles)/float(self.total_logfiles)*100))
        return 100

    @staticmethod
    @memoize
    def splitaddr(line):
        """Parses line argument which contains the source and destination
        host IP address, transport port numbers, protocol type and message
        direction. To speed up processing @memoize caches previous responses.

        Args:
            line (str): log line containing IP address and port info

        Returns:
            dict: {"direction": <str direction>, "srcip": <str srcip>,
                   "srcport": <str srcport>, "dstip": <str dstip>,
                   "dstport": <str dstport>, "proto": <str proto>}
        """
        pattern = r"(IN|OUT): ([0-9.]*):(\d+) --> ([0-9.]*):(\d+) \((\D+)\)"
        keys = ("direction", "srcip", "srcport", "dstip", "dstport", "proto")
        m = re.search(pattern, line)
        try:
            return dict((k, v) for k, v in zip(keys, m.groups()))
        except:
            return dict((k, None) for k in keys)

    @staticmethod
    def _method(lines):
        """Returns SIP message method from CSeq line.

        Args:
            lines (list): list of SIP message lines

        Returns:
            str: SIP method or empty str
        """
        try:
            hdr = next(x for x in lines if x.startswith("CSeq"))
            if hdr:
                params = hdr.split()
                if len(params) == 3:
                    return params[2]
            return ""
        except StopIteration:
            return ""

    @staticmethod
    def _is_fnu(line):
        return ("avaya-cm-fnu=off-hook" in line or
                "avaya-cm-fnu=ec500" in line)

    @staticmethod
    def strptime(s):
        """Converts SSYNDI timestamp to datetime object.

        Note:
            This is 6 times faster than datetime.strptime()

        Args:
            s (str): SSYNDI timestamp

        Returns:
            datetime obj: datetime object
        """
        return datetime(int(s[6:10]), int(s[0:2]), int(s[3:5]), int(s[11:13]),
                        int(s[14:16]), int(s[17:19]), int(s[20:26]))

    @staticmethod
    def zopen(filename):
        """Return file handle depending on file extension type:

        Args:
            filename (str): name of the logfile including path

        Returns:
            obj: file handler
        """
        if filename.endswith(".gz"):
            return gzip.open(filename)
        elif filename.endswith(".bz2"):
            return bz2.BZ2File(filename)
        else:
            return open(filename)


class ASBCE(object):
    """Simple ASBCE obejct to enable turning ON and OFF debug logging
    for SIPCC subprocess for SSYNDI and obtain basic configuration info.
    """
    SYSINFO_PATH = "/usr/local/ipcs/etc/sysinfo"
    LOGLEVEL_ERR = "Incorrect LOGLEVEL value: {0}"
    RE_FLOW = (
        r"(?P<InIf>\d+) \[",
        r"(?P<InSrcIP>[\d+.]*):",
        r"(?P<InSrcPort>\d+) -> ",
        r"(?P<InDstIP>[\d+.]*):",
        r"(?P<InDstPort>\d+)\] OUT ",
        r"(?P<OutIf>\d+) RELAY ",
        r"(?P<OutSrcIP>[\d+.]*):",
        r"(?P<OutSrcPort>\d+) -> ",
        r"(?P<OutDstIP>[\d+.]*):",
        r"(?P<OutDstPort>\d+).*in VLAN ",
        r"(?P<InVlan>\w+) out VLAN ",
        r"(?P<OutVlan>\w+) Enc ",
        r"(?P<Enc>\w+) Dec ",
        r"(?P<Dec>\w+) Snt ",
        r"(?P<Snt>\w+) Drp ",
        r"(?P<Drp>\w+) Rx ",
        r"(?P<Rx>\w+) Rly ",
        r"(?P<Rly>\w+) ECH ",
        r"(?P<Ech>\w+)",
    )

    def __init__(self, mock=False):
        """Initializes Aasbce instance.

        Args:
            mock (bool): if the instance should not make changes in the DB.
        Returns:
            obj: Asbce instance
        """
        self.mock = mock
        self.capture_active = False
        self._ifaces = None
        self._ems_ip = None
        self._mgmt_ip = None
        self._signaling_ifaces = None
        self._media_ifaces = None
        self._publics = None
        self._servers = None
        self._sysinfo = None
        self._version = None
        self._hostname = node()
        self._hardware = None
        self.lastflows = {}
        self.lastflows_timestamp = None
        self.sipcc_loglevel_inital = self.sipcc_loglevel
        self.Flow = Flow
        self.reFlow = re.compile("".join(self.RE_FLOW), re.I)

    @property
    def ems_ip(self):
        """str: Returns the EMS IP address."""
        if self._ems_ip is None:
            cmd = "ps --columns 999 -f -C ssyndi"
            output = self._exec_cmd(cmd)
            m = re.search(r"--ems-node-ip=(\d+\.\d+\.\d+\.\d+)", output)
            if not m:
                self._ems_ip = ""
            else:
                self._ems_ip = m.group(1)
        return self._ems_ip

    @property
    def ifaces(self):
        """dict: Returns the IP addresses of all interface as keys
        and interface names as values. This includes signaling, media
        and IPv6 addresses as well.
        """
        if self._ifaces is None:
            self._ifaces = {
                ifaddr["addr"]:iface for iface in interfaces() for ifaddrs in
                ifaddresses(iface).values() for ifaddr in ifaddrs
            }
            self._ifaces.update({k: self._ifaces[self.publics[k]] for k in
                        set(self.publics).difference(set(self.ifaces))})
        return self._ifaces

    @property
    def mgmt_ip(self):
        """str: Returns the IP address of the SBCE's M1 interface."""
        if self._mgmt_ip is None:
            reverse_ifaces = dict((v, k) for k, v in self.ifaces.items())
            self._mgmt_ip = reverse_ifaces.get("M1", "")
        return self._mgmt_ip

    @property
    def signaling_ifaces(self):
        """dict: Returns the IP addresses of the signaling interfaces
        as keys and namedtuples as values containing the administered
        signaling interface name and public IP address of it as values.
        """
        if self._signaling_ifaces is None:
            self._signaling_ifaces = {}
            SigIface = namedtuple('signaling_iface', ["name", "public_ip"])
            sqlcmd = "SELECT SIGNAL_NAME, IP_ADDRESS, PUBLIC_IP\
                      FROM SIP_SIGNALING_INTERFACE_VIEW"
            signaling_ifaces = self._exec_sql(sqlcmd)
            if signaling_ifaces:
                for signaling_iface in signaling_ifaces.split("\n"):
                    l = signaling_iface.replace("|", "").split()
                    name, ip, public_ip = " ".join(l[0:-2]), l[-2], l[-1]
                    self._signaling_ifaces.update({ip: SigIface(name, public_ip)})
        return self._signaling_ifaces

    @property
    def media_ifaces(self):
        """dict: Returns the IP addresses of the media interfaces
        as keys and namedtuples as values containing the administered
        media interface name, ethernet interface name and public IP address.
        """
        if self._media_ifaces is None:
            self._media_ifaces = {}
            MedIface = namedtuple("media_iface", ["name", "iface", "public_ip"])
            sqlcmd = "SELECT MEDIA_NAME, INTERFACE, IP_ADDRESS, PUBLIC_IP\
                      FROM SIP_MEDIA_INTERFACE_VIEW"
            media_ifaces = self._exec_sql(sqlcmd)
            if media_ifaces:
                for media_iface in media_ifaces.split("\n"):
                    l = media_iface.replace("|", "").split()
                    name, iface, ip, public_ip = " ".join(l[0:-3]), l[-3], l[-2], l[-1]
                    self._media_ifaces.update({ip: MedIface(name, iface, public_ip)})
        return self._media_ifaces

    @property
    def servers(self):
        """dict: Returns the IP addresses of the administered SIP servers
        as keys and namedtuples as values containing the administered SIP
        server name and its type as values.
        """
        if self._servers is None:
            self._servers = {}
            sqlcmd = "SELECT DISTINCT SERVER_CONFIG_NAME, SERVER_TYPE, SERVER_ADDRESS\
                      FROM SIP_SERVER_CONFIG, SIP_SERVER_CONFIG_ADDRESSES\
                      WHERE SIP_SERVER_CONFIG_ADDRESSES.SERVER_CONFIG_ID =\
                            SIP_SERVER_CONFIG.SERVER_CONFIG_ID"
            servers = self._exec_sql(sqlcmd)
            if servers:
                for server in servers.split("\n"):
                    l = server.replace("|", "").split()
                    name, type, ip = " ".join(l[0:-2]), l[-2], l[-1]
                    if type == "CALL_SERVER":
                        type = "Call"
                    else:
                        type = "Trk"
                    self._servers.update({ip: Server(name, type)})
        return self._servers

    @property
    def sysinfo(self):
        """str: Returns the content of the sysinfo file."""
        if self._sysinfo is None:
            with open(self.SYSINFO_PATH, "r") as handle:
                self._sysinfo = handle.read()
        return self._sysinfo

    @property
    def version(self):
        """str: Returns the software version of the SBCE in short format."""
        if self._version is None:
            m = re.search("VERSION=(.*)\n", self.sysinfo)
            if not m:
                self._version = ""
            else:
                self._version = m.group(1).split("-")[0]
        return self._version

    @property
    def publics(self):
        """dict: Returns the public/private interface map."""
        if self._publics is None:
            c = chain(self.signaling_ifaces.items(), self.media_ifaces.items())
            self._publics = dict((v.public_ip, k) for k, v in c)
        return self._publics

    @property
    def hardware(self):
        """str: Returns HARDWARE info from sysinfo."""
        if self._hardware is None:
            m = re.search("HARDWARE=(.*)\n", self.sysinfo)
            if not m:
                self._hardware = "310"
            else:
                self._hardware = m.group(1)
        return self._hardware

    @property
    def hostname(self):
        """str: Returns hostname."""
        return self._hostname

    @property
    def sipcc_loglevel(self):
        """str: Returns the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Raises:
            RuntimeError: if the returned value is something unexpected
                          so as to stop corrupting the DB further
        """
        sqlcmd = "SELECT LOGLEVEL FROM EXECUTION_LOGLEVEL\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'"
        value = self._exec_sql(sqlcmd)
        if not re.match("[01]{6}$", value):
            raise RuntimeError(value)
        return value

    @sipcc_loglevel.setter
    def sipcc_loglevel(self, value):
        """Setter method to set the value of 'LOG_SUB_SIPCC' for SSYNDI.

        Args:
            value (str): in a format of [01]{6}

        Returns:
            None

        Raises:
            ValueError: if value argument is unexpected, it can only
                differ from the current sipcc_loglevel value in position 3
                that is at index 2
        """
        pattern = "".join((self.sipcc_loglevel[:2], "[01]", self.sipcc_loglevel[3:]))
        if not re.match(pattern, value):
            raise ValueError(self.LOGLEVEL_ERR.format(value))
        sqlcmd = "UPDATE EXECUTION_LOGLEVEL SET LOGLEVEL='{0}'\
                  WHERE SUBSYSTEM='LOG_SUB_SIPCC'".format(value)
        _ = self._exec_sql(sqlcmd)

    def capture_start(self):
        """Turns on Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = True
            return True
        value = "".join((self.sipcc_loglevel[:2], "1", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = True
            return True
        return False

    def capture_stop(self):
        """Turns off Debug loglevel for 'LOG_SUB_SIPCC' subsystem.

        Returns:
            bool: True if execution was successful, False otherwise
        """
        if self.mock:
            self.capture_active = False
            return True
        value = "".join((self.sipcc_loglevel[:2], "0", self.sipcc_loglevel[3:]))
        self.sipcc_loglevel = value
        if self.sipcc_loglevel == value:
            self.capture_active = False
            return True
        return False

    def showflow(self, level=9):
        """Return the result of "showflow".

        Args:
            level (int, optional): 'showflow' verbose level

        Returns:
            list: flows in list, one flow line per list item
        """
        cmd = "showflow {0} dynamic {1}".format(self.hardware, level)
        flows = self._exec_cmd(cmd)
        return [x.strip() for x in flows.splitlines()] if flows else []

    def flowstodict(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as dictionary.

        Returns:
            dict: keys are tuples of SBCE IP and port of flows
        """
        self.lastflows = {(f["InDstIP"], f["InDstPort"]):f for f in
                          (self._flowtodict(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flowtodict(self, f):
        """Converts flow string to dict.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            dict: flow field names and values
        """
        m = self.reFlow.search(f)
        if m:
            return self._fmtflow(m.groupdict())
        return {}

    def flows(self):
        """Returns the flows as dict where a key is the SBCE IP and port
        of a flow and the value is the Flow values as namedtuple.

        Returns:
            dict: SBCE IP and port tuple as key and Flow instance as value
        """
        self.lastflows = {(f.InDstIP, f.InDstPort):f for f in
                          (self._flow(x) for x in self.showflow())}
        self.lastflows_timestamp = datetime.now()
        return self.lastflows

    def _flow(self, f):
        """Converts flow string to Flow class instance.

        Args:
            f (str): flow line from list returned by showflow

        Returns:
            Flow: Flow class instance
        """
        m = self.reFlow.search(f)
        return self.Flow(**self._fmtflow(m.groupdict())) if m else ()

    def flow(self, asbce_ip, asbce_port):
        """Combines and returns stats for flow identified by
        asbce_ip and asbce_port.

        Args:
            asbce_ip (str): SBCE audio ip address of flow
            asbce_port (str): SBCE audio RTP port of flow

        Returns:
            dict(): {<ifaceA>: Flow, <ifaceB>: Flow}
        """
        flows = self.flows()
        fwdflow = flows.get((asbce_ip, asbce_port), {})
        if fwdflow:
            revflow = flows.get((fwdflow.OutSrcIP, fwdflow.OutSrcPort), {})
            return ({fwdflow.InIf: fwdflow, revflow.InIf: revflow}
                    if revflow else {fwdflow.InIf: fwdflow})
        return {}

    @staticmethod
    def _fmtflow(flowdict, hex=False):
        """Converts hex values from flow tuple to decimal string and
        interface numbers to interface names.

        Args:
            flowdict (dict): dict returned by flowtodict
            hex (bool, optional): to convert counters from string hex to int

        Returns:
            dict: formated flowdict
        """
        for k in ("InIf", "OutIf"):
            flowdict[k] = {"0":"A1", "1":"A2", "2":"B1", "3":"B2"}.get(flowdict[k], "?")
        for k in ("InSrcPort", "InDstPort", "OutSrcPort", "OutDstPort"):
            flowdict[k] = int(flowdict[k])
        if not hex:
            for k in ("InVlan", "OutVlan", "Enc", "Dec", "Snt", "Drp", "Rx", "Rly", "Ech"):
                flowdict[k] = int(flowdict[k], 16)
        return flowdict

    def _exec_sql(self, sqlcmd):
        """Helper funtion to build SQL command.

        Args:
            sqlcmd (str): executable SQL command string

        Returns:
            str: return value of self._exec_cmd
        """
        if os.path.isdir("/var/lib/pgsql/"):
            cmd = " ".join(("psql -t -U postgres sbcedb -c \"", sqlcmd, "\""))
        else:
            cmd = " ".join(
                ("solsql -a -x onlyresults -e \"", sqlcmd, "\"",
                 "\"tcp {0} 1320\" savon savon".format(self.ems_ip))
            )
        return self._exec_cmd(cmd).strip()

    @staticmethod
    def _exec_cmd(cmd):
        """Helper method to execute the SQL command.

        Args:
            cmd (str): complete SQL client command executable from bash

        Returns:
            str: return value from database command

        Raises:
            RuntimeError: if the SQL bash command returns error
        """
        proc = Popen(shlex.split(cmd), shell=False, stdout=PIPE, stderr=PIPE)
        data, err = proc.communicate()
        if proc.returncode == 0:
            return data
        raise RuntimeError(err)

    def _restore_loglevel(self):
        """Restores SIPCC loglevel to its initial value."""
        if not self.mock:
            self.sipcc_loglevel = self.sipcc_loglevel_inital


if __name__ == '__main__':
    asbce = ASBCE()
    print(asbce.mgmt_ip)
    print(asbce.ifaces)
    print(asbce.servers)
    print(asbce.hardware)
