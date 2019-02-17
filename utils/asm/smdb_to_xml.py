#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
'''
##############################################################################
## Name: smdb_to_xml
## Description: extracts NRP data from SM6.3 or 7.0 database.
## Options: see help, -h
## Version: see option -v
## Date: 2016-02-25
## Author: szokoly@avaya.com
##############################################################################
'''
import os
os.nice(19)
import pipes
import sys
import re
import time
import zipfile
try:
    import zlib
    compression = zipfile.ZIP_DEFLATED
except:
    compression = zipfile.ZIP_STORED
import xml.dom.minidom
from optparse import OptionParser, SUPPRESS_HELP
from subprocess import Popen, PIPE
try:
    import pg
    has_pygresql = True
except:
    has_pygresql = False

prolog = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
dbname = "asm"
pguser = "postgres"
pgpassword = "postgres"
pghost = "localhost"
pgport = 5432
retain = False
fixup = False
has_dpt = False
version = "1.0.3"
author = "szokoly@avaya.com"
installprops = "/opt/Avaya/install.properties"
expiry = "181230"
zip_filename = "NRPExportData"
rePrettify = re.compile(r">\n\s+([^<>\s].*?)\n\s+</", re.DOTALL)
reRelease = re.compile(r"(\d+.\d+.\d+)")
green = "\033[1;32m"
red = "\033[1;31m"
standout = "\033[1;37m"
white = "\033[0;m"

def get_release():
    global dbname
    release = ""
    try:
        f = open(installprops)
        for line in f:
            if line.startswith("Release="):
                release = reRelease.search(line).group(1)
                break
        f.close()
    except:
        cmd = ["/bin/bash", "-i", "-c", "swversion"]
        p = Popen(cmd, env=os.environ.copy(), stdout=PIPE, stderr=PIPE)
        data = p.communicate()[0].strip()
        pos = data.find("Release: ")
        if pos > -1:
            release = reRelease.search(data[pos+9:pos+15]).group(1)
        else:
            pos = data.find("Software Update Revision: ")
            if pos > -1:
                release = re.search(r"(\d+.\d+.\d+)", data[pos+26:pos+41]).group(1)
                dbname = "avmgmt"
    return release

def parse_options():
    global pguser, pgpassword, dbname, retain, fixup
    if os.getuid() != 0:
        print "ERROR: only 'root' can run this tool."
        sys.exit(1)
    if time.time() > time.mktime(time.strptime(str(expiry), "%y%m%d")):
        print "ERROR: this program has expired, please download a fresh copy."
        sys.exit(1)
    parser = OptionParser(usage='%prog [<options>]', description="This\
 tool exports the NRP data from Session Manager 6.3.x or 7.0 database\
 and creates a NRPExportData.zip file with the following xml files in it:\
        1_Domains.xml                                                                   \n\
        2_Locations.xml                                                                  \n\
        3_Adaptations.xml                                                               \n\
        4_SipEntities.xml                                                                 \n\
        5_EntityLinks.xml                                                                 \n\
        6_TimeRanges.xml                                                               \n\
        7_RoutingPolicies.xml                                                            \n\
        8_DialPatterns.xml                                                                \n\
        9_RegularExpressions.xml")
    parser.add_option('--pguser', action='store', default=False, dest='pguser',\
                        help='to overwrite the default database user "postgres"')
    parser.add_option('--pgpassw', action='store', default=False, dest='pgpassw',\
                        help='to overwrite the default database user password')
    parser.add_option('--dbname', action='store', default=False, dest='dbname',\
                        help=SUPPRESS_HELP)
    parser.add_option('--fixup', action='store_true', default=False, dest='fixup',\
                        help=SUPPRESS_HELP)
    parser.add_option('--retain', action='store_true', default=False, dest='retain',\
                        help='to not delete the individual xml files upon completion')
    parser.add_option('-v', action='store_true', default=False, dest='version',\
                        help='to print version number and exit')
    parser.add_option('--author', action='store_true', default=False, dest='author',\
                        help=SUPPRESS_HELP)
    opts = parser.parse_args()[0]
    if opts.version:
        print version + "  (Expiry date: %s)" % expiry
        sys.exit()
    if opts.retain:
        retain = True
    if opts.pguser:
        pguser = opts.pguser.strip()
    if opts.pgpassw:
        pgpassword = opts.pgpassw.strip()
    if opts.dbname:
        dbname = opts.dbname.strip()
    if opts.author:
        print author
        sys.exit()
    if opts.fixup:
        fixup = True

#Release dependent elements
release = get_release()
if release.startswith("7"):
    securable = ", s.securable"
elif release.startswith("6.3"):
    if release == "6.3.0" or release == "6.3.1":
        loop_detect_interval_msec = ""
        loop_detect_mode = ""
        loop_detect_threshold = ""
    else:
        loop_detect_interval_msec = "s.loop_detect_interval_msec, "
        loop_detect_mode = "s.loop_detect_mode, "
        loop_detect_threshold = "s.loop_detect_threshold, "
    securable = ""
else:
    if dbname == "avmgmt":
        appl = "System Manager"
    else:
        appl = "Session Manager"
    print "ERROR: you must run this tool on %s 6.3 or above, exiting..." % appl
    sys.exit(1)

parse_options()

#Fixups - to not export certain elements which can break import
if fixup:
    DptFsSipentityName = ""
    dpt_in_survivable_mode = ""
    listed_directory_number = ""
else:
    DptFsSipentityName = ", s.name as DptFsSipentityName,"
    dpt_in_survivable_mode = "r.dpt_in_survivable_mode,"
    listed_directory_number = "r.listed_directory_number"

#NRP Tables
DOMAINS = """
SELECT xmlelement(name "sipdomainFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "SipdomainFullTO",
        xmlforest(
            c.description as "notes",
            c.defaultdomain as "defaultDomain",
            c.domainname as "domainName",
            t.name as "domainType",
            coalesce(s.name, c.domainname) as "name"
                     )
                 ) ORDER BY c.scrush_id 
            ))
FROM csdomain c 
LEFT JOIN csdomaintypeenum t ON (c.csdomaintypeid = t.id) 
LEFT JOIN sipdomain s ON (c.scrush_id = s.id) 
WHERE c.scrush_id is not NULL;"""

LOCATIONS = """
SELECT xmlelement(name "routingoriginationFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "RoutingoriginationFullTO",
        xmlforest(
            r.notes,
            r.name,
            r.cac_audio_alarm_latency,
            r.cac_audio_alarm_threshold_percent,
            r.cac_avg_bwidth_percall as "AverageBandwidthPerCall",
            r.cac_avg_bwidth_percall_uom as "AverageBandwidthPerCallUnitOfMeasurement",
            r.cac_can_audio_steal_from_video,
            r.cac_max_bwidth_video_interloc,
            r.cac_max_bwidth_video_intraloc,
            r.cac_min_acceptable_bwidth_video,
            r.cac_tot_bwidth_allow as "ManagedBandwidth",
            r.cac_tot_bwidth_allow_uom as "ManagedBandwidthUnitOfMeasurement",
            r.cac_video_alarm_latency,
            r.cac_video_alarm_threshold_percent
            %s
            %s
            %s),
            (SELECT xmlagg(
                xmlelement(name "routingoriginationpatterns",
                xmlelement(name "notes", p.notes),
                xmlelement(name "ipaddresspattern", p.ipaddresspattern)
                ))
            FROM routingoriginationpattern p
            WHERE p.routingorigination_id = r.id),
        xmlforest(
            r.time_to_live_sec as "TimeToLiveInSec")
            )))
FROM routingorigination r
LEFT JOIN sipentity s ON (r.dpt_fs_sipentity_id= s.id);""" % (DptFsSipentityName, dpt_in_survivable_mode, listed_directory_number)

ADAPTATIONS = """
SELECT xmlelement(name "adaptationFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "AdaptationFullTO",
        xmlforest(a.notes,
            a.adaptationmodule,
            a.egressuriparameters,
            a.name),
        (SELECT xmlagg(
                    xmlelement(name "EgressadaptationFullTO",
                        xmlforest(
                            e.notes,
                            e.additional_data as "adaptationdata",
                            e.deletedigits,
                            e.insertdigits,
                            e.matchingpattern,
                            e.maxdigits,
                            e.mindigits,
                            e.phone_context as "phoneContext"
                            ),
                    xmlelement(name "adaptation",
                        xmlforest(
                            a.notes,
                            a.adaptationmodule,
                            a.egressuriparameters,
                            a.name
                            )),
                    xmlforest(
                            e.addresstomodify as "addressToModify"
                                )
                            ))
        FROM egressadaptation e
        WHERE a.id = e.adaptation_id),
        (SELECT xmlagg(
                  xmlelement(name "IngressadaptationFullTO",
                  xmlforest(
                        i.notes,
                        i.additional_data as "adaptationdata",
                        i.deletedigits,
                        i.insertdigits,
                        i.matchingpattern,
                        i.maxdigits,
                        i.mindigits,
                        i.phone_context as "phoneContext"
                                ),
                  xmlelement(name "adaptation",
                        xmlforest(
                            a.notes,
                            a.adaptationmodule,
                            a.egressuriparameters,
                            a.name
                                 )),
                  xmlforest(
                            i.addresstomodify as "addressToModify"
                                )
                            ))
        FROM ingressadaptation i
        WHERE a.id = i.adaptation_id)           
        )))
FROM adaptation a;"""

SIPENTITIES = """
SELECT xmlelement(name "sipentityFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "SipentityFullTO",
        xmlforest(
            s.notes,
            s.entitytype,
            s.fqdnoripaddr,
            s.name,
            a.name as "adaptationName",
            s.cac_capable,
            s.cdrsetting as "cdrSetting",
            s.commprofile_type_for_preferredhandle as "commproftype",
            s.credentialname,
            s.do_monitoring),
            (SELECT 
                xmlagg(
                    xmlelement(name "listenports",
                    xmlelement(name "notes", l.notes),
                    xmlelement(name "portnumber", l.portnumber),
                    xmlelement(name "sipdomainName", d.name),
                    xmlelement(name "transportprotocol", l.transportprotocol)
                                    ) ORDER BY l.portnumber
                            )
            FROM listenport l
            LEFT JOIN sipdomain d ON (l.sipdomain_id = d.id)
            WHERE s.id = l.sipentity_id),
        xmlforest(
            %s
            %s
            %s
            s.monitor_proactive_secs,
            s.monitor_reactive_secs,
            s.monitor_retries,
            b1.name as "primaryBandwidthManagerName",
            b2.name as "secondaryBandwidthManagerName",
            o.name as "routingoriginationName"
            %s),
            (SELECT
                xmlagg(
                    xmlelement(name "sipmonresponsehandlings",
                    xmlelement(name "notes", r.comment),
                    xmlelement(name "response", r.response),
                    xmlelement(name "type", r.type)
                                    )
                            )
            FROM sipmonresponsehandling r
            WHERE s.id = r.sipentity_id),
        xmlforest(
            s.tcp_failover_port,
            s.timer_bf_secs,
            t.name as "timezoneName",
            s.tls_failover_port,
            s.userfc3263)
            ) ORDER BY s.entitytype))
FROM sipentity s 
LEFT JOIN timezone t ON (s.timezone_id = t.id) 
LEFT JOIN sipentity b1 ON (s.bandwidth_sharing_sm1_id = b1.id) 
LEFT JOIN sipentity b2 ON (s.bandwidth_sharing_sm2_id = b2.id) 
LEFT JOIN routingorigination o ON (s.routingorigination_id = o.id) 
LEFT JOIN adaptation a ON (s.adaptation_id = a.id);""" % (loop_detect_interval_msec, loop_detect_mode, loop_detect_threshold, securable)

ENTITYLINKS = """
SELECT xmlelement(name "entitylinkFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "EntitylinkFullTO",
        xmlelement(name "notes", e.notes),
        xmlelement(name "connectionPolicy", e.connection_policy),
        xmlelement(name "listenPortEntity1", e.listenportentity1),
        xmlelement(name "listenPortEntity2", e.listenportentity2),
        xmlelement(name "name", e.name),
        xmlelement(name "serviceState", e.service_state),
        xmlelement(name "transportProtocol", e.transportprotocol),
        xmlelement(name "trusted", e.trusted),
        xmlelement(name "entityName1", s1.name),
        xmlelement(name "entityName2", s2.name)
            )))
FROM entitylink e 
LEFT JOIN sipentity s1 ON (e.entity1_id = s1.id) 
LEFT JOIN sipentity s2 ON (e.entity2_id = s2.id);"""

TIMERANGES = """
SELECT xmlelement(name "timerangeFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "TimerangeFullTO",
        xmlforest(notes,
            includesfriday as "includesFriday",
            includesmonday as "includesMonday",
            includessaturday as "includesSaturday",
            includessunday as "includesSunday",
            includesthursday as "includesThursday",
            includestuesday as "includesTuesday",
            includeswednesday as "includesWednesday",
            name,
            starttime as "startTime",
            stoptime as "stopTime")
            )))
FROM timerange;"""

ROUTINGPOLICIES = """
SELECT xmlelement(name "routingpolicyFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "RoutingpolicyFullTO",
        xmlforest(
            r.notes,
            r.disabled,
            r.name,
            r.retries,
            s.name as "sipentityName"
            ),
        (SELECT xmlagg(
            xmlelement(name "timeofdayNames",
            xmlelement(name "rank", t.rank),
            xmlelement(name "timerangeName", g.name)
            ))
        FROM timeofday t
        LEFT JOIN timerange g ON (t.timerange_id = g.id)
        WHERE r.id = t.routingpolicy_id)
         )))
FROM routingpolicy r 
LEFT JOIN sipentity s ON (s.id = r.sipentity_id);"""

DIALPATTERNS = """
SELECT xmlelement(name "digitmapFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "DigitmapFullTO",
        xmlforest(
            d.notes,
            d.deny,
            d.digitpattern,
            d.emergency_desc,
            d.emergency_order,
            d.maxdigits,
            d.mindigits,
            r.name as "routingoriginationName"
                 ),
       (SELECT xmlagg(
                  xmlelement(name "routingpolicyNames", p.name)
                    )
        FROM routingpolicy p
        LEFT JOIN digitmaptopolicy m ON (p.id = m.routingpolicy_id)
        WHERE d.id = m.digitmap_id),
        xmlforest(
            s.name as "sipdomainName",
            d.treatasemergency as "treatasemergency")
            )))
FROM digitmap d 
LEFT JOIN routingorigination r ON (d.routingorigination_id = r.id) 
LEFT JOIN sipdomain s ON (d.sipdomain_id = s.id);"""

REGULAREXPRESSIONS = """
SELECT xmlelement(name "regexpmapFullTOList",
    xmlelement(name "buildNumber", 0),
    xmlelement(name "implementationVersion", 0),
    xmlelement(name "specificationVersion", 0),
    xmlagg(xmlelement(name "RegexpmapFullTO",
        xmlforest(
            r.notes,
            r.deny,
            r.pattern,
            r.rankorder
                 ),
       (SELECT xmlagg(
                  xmlelement(name "routingpolicyNames", p.name)
                     )
        FROM routingpolicy p
        LEFT JOIN regexpmaptopolicy m ON (p.id = m.routingpolicy_id)
        WHERE r.id = m.regexpmap_id)
            )))
FROM regexpmap r;"""

def write_to_disk(fname, raw):
    global has_dpt
    count = 0
    node = tables[fname][1]
    if fname == "2_Locations.xml":
        if raw.find("dptfssipentityname") > -1:
            has_dpt = True
    try:
        parsedXml = xml.dom.minidom.parseString(raw)
    except:
        print "ERROR: xml parsing failed in %s, aborting..." % fname
        sys.exit(1)
    indentedXml = parsedXml.toprettyxml(indent="    ")
    prettyXml = rePrettify.sub(">\g<1></", indentedXml)
    f = open(fname, "w")
    f.write(prolog)
    for line in prettyXml.splitlines()[1:]:
        if node in line:
            count += 1
        if line.endswith("/>"):
            line = line[:-2] + "></" + line.strip()[1:-2] + ">"
        f.write(line)
        f.write("\n")
    print "".join(("[", green, "OK", white, "]", " Exported: ", standout, str(count), white))
    f.close()

if __name__ == "__main__":
    tables = {
    "1_Domains.xml" : (DOMAINS, "</SipdomainFullTO>"),
    "2_Locations.xml" : (LOCATIONS, "</RoutingoriginationFullTO>"),
    "3_Adaptations.xml" : (ADAPTATIONS, "</AdaptationFullTO>"),
    "4_SipEntities.xml" : (SIPENTITIES, "</SipentityFullTO>"),
    "5_EntityLinks.xml" : (ENTITYLINKS, "</EntitylinkFullTO>"),
    "6_TimeRanges.xml" : (TIMERANGES, "</TimerangeFullTO>"),
    "7_RoutingPolicies.xml" : (ROUTINGPOLICIES, "</RoutingpolicyFullTO>"),
    "8_DialPatterns.xml" : (DIALPATTERNS, "</DigitmapFullTO>"),
    "9_RegularExpressions.xml" : (REGULAREXPRESSIONS, "</RegexpmapFullTO>"),
    }
    print 52 * "-"
    print "Detected Release %s " % release
    os.environ['PGPASSWORD'] = pgpassword
    if has_pygresql:
        print "Using 'PyGreSQL' library to query '%s' database" % dbname
        print 52 * "-"
        try:
            conn = pg.connect(dbname, pghost, pgport, None, None, pguser, pgpassword)
        except pg.InternalError, err:
            print err
            sys.exit(1)
    else:
        env = dict(os.environ, PGPASSWORD=pgpassword)
        print "Using 'psql' bash command to query '%s' database" % dbname
        print 52 * "-"
    for filename in sorted(tables.keys()):
        print ("Creating %s" % filename.ljust(28)),
        if has_pygresql:
            data = conn.query(tables[filename][0])
            result = data.getresult()[0][0].strip()
        else:
            cmd = 'psql -t -w -h %s -p %s -U %s -d %s -c %s' % (
                pghost, pgport, pguser, dbname, pipes.quote(tables[filename][0]))
            p = Popen(cmd, shell=True, env=env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            data, err = p.communicate()
            if err:
                print err
                sys.exit(1)
            result = data.strip()
        write_to_disk(filename, result)
    if has_pygresql:
        conn.close()
    if fixup:
        zip_filename += "_fixup.zip"
    else:
        zip_filename += ".zip"
    print 52 * "-"
    print "Creating %s" % zip_filename
    zf = zipfile.ZipFile(zip_filename, mode='w')
    try:
        for filename in tables:
            zf.write(filename, compress_type=compression)
    finally:
        zf.close()
    if not retain:
        print "Removing temporary files"
        for filename in tables:
            os.remove(filename)
    print "Done!"
    if has_dpt and not fixup:
        print "%s:  Reference to a SIP Entity is found in at least one Location." % ''.join((red, "Warning", white))
        print "\t  Importing %s in SMGR may produce error." % (''.join((standout, "2_Locations.xml", white)))
        print "\t  If so try running this script again with %s option." % (''.join((standout, "--fixup", white)))
        print "\t  Import the created %s first." % (''.join((standout, "NRPExportData_fixup.zip", white)))
        print "\t  Then proceed importing %s again." % (''.join((standout, "NRPExportData.zip", white)))
