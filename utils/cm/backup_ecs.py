#!/usr/bin/env python
import glob
import gzip
import os
os.nice(19)
import shutil
import sys

SRCDIR='/var/log/ecs'
DSTDIR='/var/home/ftp/pub/ecsbkp'
FILES='20*'
MAXUSE=90
GZIP=1
RATIO=4
DEBUG=0

HELP='''This script takes no argument, the configurable parameters must be 
edited in the script file. See below the meaning of these parameters:

SRCDIR Specifies the source folder where the log files are backed up from.
       This is normally the /var/log/ecs folder where the ecs files are.
DSTDIR Specifies the destination folder where the log files are backed up to.
       This is by default the /var/home/ftp/pub/ecsbkp folder, which will be
       created if does not yet exist when the script runs.
FILES  Specifies the pattern of files to be backed up, expanded by shell.
MAXUSE Determines the maximum %% of space that can be used up on the partition
       of the DSTDIR folder. The default is 90 percent.
GZIP   Determines if the backup is to be gzip compressed or not. The default
       is 1 which means it is.
RATIO  Gzip compression level, 9 slowest/most compression, 0 no compression.
DEBUG  This is for debugging purposes. It should be left as 0 when the script
       is run by cron.

The current values are:

SRCDIR=%s
DSTDIR=%s
FILES=%s
MAXUSE=%s
GZIP=%s
RATIO=%s
DEBUG=%s
'''

def prerun_checks(srcdir, dstdir, debug=0):
    if not os.path.isdir(srcdir) and not os.path.exists(srcdir):
        raise EnvironmentError('Source folder %s is not valid!' % srcdir)
    if not os.path.exists(dstdir):
        os.makedirs(dstdir)
        if debug:
            print 'prerun_checks: created %s' % dstdir
    elif not os.path.isdir(dstdir):
        raise EnvironmentError('Destination folder %s is not valid!' % dstdir)

def disk_usage(path, debug=0):
    space_st = os.statvfs(path)
    avail = space_st.f_frsize * space_st.f_bavail
    total = space_st.f_frsize * space_st.f_blocks
    used = total - avail
    usage = {
        'total': total,
        'used': used,
        'avail': avail,
        'percent': int(round(100 * (float(used) / total)))
    }
    if debug:
        print 'disk_usage: %s %s' % (path, usage)
    return usage

def compress(srcfile, dstdir, compresslevel=4):
    try:
        basename = os.path.basename(srcfile)
        gzipfile = os.path.join(dstdir, basename + '.gz')
        fd_in = open(srcfile, 'rb')
        fd_out = gzip.open(gzipfile, 'wb', compresslevel)
        shutil.copyfileobj(fd_in, fd_out)
    finally:
        fd_in.close()
        fd_out.close()

def glob_files(path, files, reverse=False):
    os.chdir(path)
    l = sorted(glob.glob(files), reverse=reverse)
    result = []
    for filename in l:
        if filename.endswith('.gz'):
            result.append(filename[:-3])
        else:
            result.append(filename)
    return result

def sweep(srcdir, dstdir, files, maxuse=90, gzip=1, ratio=4, debug=0):
    srcfiles = glob_files(srcdir, files)[:-1]
    bkpfiles = glob_files(dstdir, files, True)
    newfiles = sorted(set(srcfiles).difference(set(bkpfiles)))
    if debug:
        print 'sweep: srcfiles 0:%s, -1:%s' % (srcfiles[:1], srcfiles[-1:])
        print 'sweep: bkpfiles 0:%s, -1:%s' % (bkpfiles[-1:], bkpfiles[:1])
        print 'sweep: newfiles 0:%s, -1:%s' % (newfiles[:1], newfiles[-1:])
    for newfile in newfiles:
        retried = False
        if bkpfiles:
            oldest = bkpfiles[-1]
            if oldest >= newfile:
                if debug:
                    print 'sweep: newfile is older than oldest bkp, skipping'
                continue
        while disk_usage(dstdir)['percent'] >= maxuse:
            try:
                oldest = bkpfiles.pop()
                if debug:
                    print 'sweep: popped %s' % oldest
            except IndexError:
                if retried:
                    return
                bkpfiles = glob_files(dstdir, files, True)
                retried = True
                if debug:
                    print 'sweep: retrying with already copied files'
            else:
                glob_oldest = os.path.join(dstdir, oldest + '*')
                for oldest in glob.glob(glob_oldest):
                    os.remove(oldest)
                if debug:
                    print 'sweep: removed %s' % oldest
        srcfile = os.path.join(srcdir, newfile)
        if gzip:
            compress(srcfile, dstdir, ratio)
            if debug:
                print 'sweep: copied and compressed %s' % srcfile
        else:
            shutil.copy2(srcfile, dstdir)
            if debug:
                print 'sweep: copied %s' % srcfile

def main():
    if len(sys.argv) > 1:
        print HELP % (SRCDIR, DSTDIR, FILES, MAXUSE, GZIP, RATIO, DEBUG)
        return 1
    prerun_checks(SRCDIR, DSTDIR, DEBUG)
    sweep(SRCDIR, DSTDIR, FILES, MAXUSE, GZIP, RATIO, DEBUG)

if __name__ == '__main__':
    sys.exit(main())
