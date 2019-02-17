#!/usr/bin/python
'''
#############################################################################
# Description: connects to the WebLM server - provided as argument and
#              imports the last certificate from the certificate chain 
#              presented by the server to the SBCE's WebLM client keystore.
# Options: see help, -h
# Date: 2016-07-13
# Author: szokoly@protonmail.com
#############################################################################
'''
import M2Crypto
import os
import re
import shutil
import socket
import sys
from subprocess import Popen, PIPE
from optparse import OptionParser, SUPPRESS_HELP

SYSINFO = '/usr/local/ipcs/etc/sysinfo'
JKS_DIR = '/usr/local/weblm/etc/'
JKS_CERT_FILE = 'trusted_weblm_certs.jks'
HOME_DIR = '/home/ipcs/'
WEBLM_CERT = HOME_DIR + 'weblm.pem'
WEBLM_PORT = 52233
KEYTOOL = '/usr/bin/keytool'
PASSWORD = 'password'
VERSION = '0.1'
ALIAS = 'weblm'
DEBUG = False

if not hasattr(__builtins__, 'next'):
    """
    This for situation when script is run in SBCE 6.2 or earlier
    where python 2.4 did not have this built-in function.
    """
    def next(it):
        return it.next()

def validate_ip(ip):
    """
    Checks IP address, returns True if it is valid.
    """
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and not False in [(int(n) <= 255) for n in m.groups()]

def platform_ok():
    """
    For now this only checks if version is 6.3 or above and if the
    default keystore file exists.
    """
    try:
        fd = open(SYSINFO)
        lines = fd.read().splitlines() 
        fd.close()
        vline = next(line for line in lines if line.startswith('VERSION'))
        version = vline.split('=')[1]
        if int(version[:5].replace('.', '')) < 630:
            return False
    except IOError:
        return False
    if not os.path.exists(JKS_DIR+JKS_CERT_FILE):
        return False
    return True

def get_host_port(host):
    """
    Parses host argument in case it is provided with PORT number.
    """
    if ':' in host:
        host, port = host.split(':')
    else:
        port = WEBLM_PORT
    if validate_ip(host):
        return host, int(port)
    else:
        print 'ERROR: found invalid IP address.'
        sys.exit(1)

def backup_keystore():
    """
    Creates a backup of the original keystore file.
    """
    jks_original = JKS_DIR + JKS_CERT_FILE
    jks_backup = jks_original + '.bkp'
    print 'Creating backup of %s to %s' % (jks_original, jks_backup)
    shutil.copy2(jks_original, jks_backup)

def get_weblm_cacert(host, port):
    """
    Probles WebLM server, opens an TLS connection in order to
    acquire it's certificate chain. It assumes that the last certificate
    is a CA root certificate and the chain is complete.
    """
    try:
        print 'Connecting to WebLM Server %s:%s' % (host, port)
        context = M2Crypto.SSL.Context('tlsv1')
        context.set_allow_unknown_ca(True)
        context.set_verify(M2Crypto.SSL.verify_none, True)
        conn = M2Crypto.SSL.Connection(context)
        try:
            conn.connect((host, port))
        except socket.error, err:
            print 'ERROR: %s' % err
            sys.exit(2)
        except Exception, err:
            print 'WARNING: %s' % err
        cert_chain = conn.get_peer_cert_chain()
        if len(cert_chain) > 0: 
            rootca = cert_chain[-1]
            not_before = rootca.get_not_before().get_datetime()
            not_after = rootca.get_not_after().get_datetime()
            print 'ROOT CA CERTIFICATE DETAILS'
            print 27 * '='
            print 'Owner: %s' % rootca.get_subject().as_text()
            print 'Issuer: %s' % rootca.get_issuer().as_text()
            print 'Valid from: %s  until: %s' % (not_before, not_after)
            print 27 * '='
            print 'Dumping the certificate above into %s' % (WEBLM_CERT)
            rootca.save_pem(WEBLM_CERT)
        else:
            print "No certificate found."
            sys.exit(2)
    finally:
        conn.close()

def import_weblm_cacert(cert):
    """
    Imports the WebLM root CA certificate dumped into /home/ipcs/weblm.pem
    to the WebLM client keystore, /usr/local/weblm/etc/trusted_weblm_certs.jks.
    """
    backup_keystore()
    my_env = os.environ
    cmd = '%s -import -keystore %s -alias %s -file %s -noprompt -storepass %s' % (
        KEYTOOL,
        JKS_DIR + JKS_CERT_FILE,
        ALIAS,
        WEBLM_CERT,
        PASSWORD)
    print 'Importing %s to %s' % (WEBLM_CERT, JKS_DIR + JKS_CERT_FILE)
    p = Popen(cmd, shell=True, env=my_env, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if out:
        print out
    if err:
        print err

if __name__ == '__main__':
    try:
        if os.getuid() != 0:
            print "ERROR: only 'root' can run this script."
            sys.exit(1)
        parser = OptionParser(
            usage='%prog <WebLM IP[:PORT]>', 
            description="This script imports the last certificate from the certificate\
     chain presented by the WebLM server into the SBCE's WebLM client keystore.")
        parser.add_option('--alias',
            action='store',
            default=False,
            dest='alias', 
            metavar='<name>',
            help="alias name to be used in the keystore for the to be imported\
     certificate, the is default 'weblm'")
        parser.add_option('-p',
            action='store',
            default=False,
            dest='passwd', 
            metavar='<passwd>',
            help="keystore password, the is default 'password'")
        parser.add_option('-d',
            action='store_true',
            default=False,
            dest='debug', 
            help="dry run, only dumps WebLM server's root certificate without\
     adding it to the SBCE's WebLM client keystore")
        parser.add_option('-v', '--version',
            action='store_true',
            default=False,
            dest='version',
            help="show version number and exit")
        opts, args = parser.parse_args()
        if opts.version:
            print VERSION
            sys.exit()
        if opts.debug:
            DEBUG = True
        if opts.alias:
            ALIAS = opts.alias
        if opts.passwd:
            PASSWORD = opts.passwd
        if len(args) != 1:
            print parser.print_help()
            sys.exit(1)
        if not platform_ok():
            print 'ERROR: this script runs on SBCE EMS version 6.3 or above.'
            sys.exit(1)
        else:
            host, port = get_host_port(args[0])
            get_weblm_cacert(host, port)
            if not DEBUG:
                ok = raw_input('Proceed with importing? [y/n]: ')
                if ok.lower() == 'n':
                    print 'Aborted...'
                    sys.exit(3)
                import_weblm_cacert(WEBLM_CERT)
            print 'Bye!'
    except KeyboardInterrupt:
        print '\nCaught KeyboardInterrupt, exiting...'
        sys.exit(1)
