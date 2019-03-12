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

def find_tracesbc_bytime(logfiles=None, timeframe="", type="sip"):
    logdir = "/archive/log/tracesbc/tracesbc_%s" % type
    filename_pattern = "tracesbc_%s_[1-9][0-9][0-9][0-9]*" % type
    timeframe_pattern = "(\d{4})(\d{0,2})?(\d{0,2})?:?(\d{0,2})?(\d{0,2})?"
    
    def strtepoch(s):
        m = re.search(timeframe_pattern, s)
        dt = datetime(*(int(x) if x else 1 for x in m.groups()))
        return int(time.mktime(dt.timetuple()))
    
    if logfiles is None:
        path = os.path.join(logdir, filename_pattern)
        logfiles = sorted((x for x in glob(path)))
    else:
        logfiles = sorted((x for x in logfiles if
                           re.search(filename_pattern, x)))
    
    start, sep, end = timeframe.partition('-')
    if not start:
        return logfiles
    start_epoch = str(strtepoch(start))
    try:
        first = next(x for x in logfiles if
                     os.path.basename(x)[13:24] >= start_epoch)
        first_index = logfiles.index(first)
        if first_index > 0:
            first_index -= 1
    except StopIteration:
        if logfiles and os.path.basename(logfiles[-1])[13:24] <= start_epoch:
            return logfiles[-1:]
        return []
    
    if end:
        end_epoch = str(strtepoch(end))
        try:
            last = next(x for x in logfiles if
                        os.path.basename(x)[13:24] > end_epoch)
            last_index = logfiles.index(last)
        except StopIteration:
            last_index = len(logfiles)
    else:
        last_index = len(logfiles)
    return logfiles[first_index:last_index]

def find_ssyndi_bytime(timeframe=""):
    logdir = "/usr/local/ipcs/log/ss/logfiles/elog/SSYNDI"
    ssyndi_glob = "SSYNDI_*_ELOG_*"
    pattern = "SSYNDI_\d+_ELOG_(\d+)_(\d+)_(\d+)_?(\d+)?_?(\d+)?_?(\d+)?"
    
    def order(filename):
        m = re.search(pattern, filename)
        mm, dd, yyyy, HH, MM, SS = m.groups()
        return "".join(x for x in (yyyy, mm, dd, HH, MM, SS))
    
    def is_s1gts2(ssyndi1, ssyndi2):
        return ssyndi1 == max((ssyndi1, ssyndi2), key=order)
    
    def build_name(t):
        t = t.replace(":", "")
        ph = os.path.basename(logfiles[0]).split("_", 2)[1]
        keys = ("ssyndi", "ph", "elog", "mm", "dd", "yyyy", "HH", "MM", "SS")
        d = dict(zip(("mc", "yy", "mm", "dd", "HH", "MM", "SS"), (wrap(t,2))))
        yyyy = d["mc"] + d["yy"]
        d.update({"elog": "ELOG", "ph": ph, "ssyndi": "SSYNDI", "yyyy": yyyy})
        return "_".join(x for x in (d.get(x, "00") for x in keys) if x)
    
    path = os.path.join(logdir, ssyndi_glob)
    logfiles = sorted(glob(path), key=order)
    if not logfiles:
        return []
    
    start, _, end = timeframe.partition('-')
    if not start:
        return logfiles
    s2 = build_name(start)
    l = list(filter(lambda x:is_s1gts2(os.path.basename(x), s2), logfiles))
    if not l:
        return []
    first_index = logfiles.index(l[0])  
    
    if not end:
        return logfiles[first_index:]
    s2 = build_name(end)
    l = list(filter(lambda x:is_s1gts2(os.path.basename(x), s2), logfiles))
    if not l:
        return logfiles[first_index:]
    last_index = logfiles.index(l[0])
    if last_index > 0:
        first_index -= 1
    return logfiles[first_index:last_index]

