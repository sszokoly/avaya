# backup_ecs #

This script is supposed to be run in crontab and backs up the ecs logs files of Avaya Communication Manager
to a desired destination folder. The Avaya Communication Manager by default retains the last 1000 ecs log files.
A new ecs log file is created when the size of the file reaches 1MByte or every seconds. In a busy system when
MST trace is configured so that it generated and writes out lot of data to the ecs log files the worst case scenario
is that the system keeps only the last 1000 seconds worth of data which is often not enough. To keep a copy of a larger
set of ecs log files configure and use this script. There is always a partition on the system where plenty of 
disk space is available. You should edit this file with the desired parameters then add it to crontab (crontab -e)
to run it every 10 mins or less if need to, for example in crontab:

### Example ###
```
*/10 * * * * /usr/bin/python /var/home/admin/backup_ecs.py 
```

### Parameters ###

```
SRCDIR Specifies the source folder where the log files are backed up from.
       This is normally the /var/log/ecs folder where the ecs files are.
DSTDIR Specifies the destination folder where the log files are backed up to.
       This is by default the /var/home/ftp/pub/ecsbkp folder, which will be
       created if does not yet exist when the script runs.
FILES  Specifies the shell glob pattern of files to be backed up.
MAXUSE Determines the maximum % of space that can be used up on the partition
       of the DSTDIR folder. The default is 90 percent.
GZIP   Determines if the backup is to be gzip compressed or not. The default
       is 1 which means it is.
RATIO  Gzip compression level, 9 slowest/most compression, 0 no compression.
```

### Defaults ###

```
SRCDIR='/var/log/ecs'
DSTDIR='/var/home/ftp/pub/ecsbkp'
FILES='20*'
MAXUSE=90
GZIP=1
RATIO=4
DEBUG=0
```

When running this script is no longer required it is highly recommended to delete the backup files in addition
to removing the script from crontab (crontab -r) as large amount of files left in certain folders will cause the
CM OS/Security/XLN backup utility to fail. Also make be to remove the correct ecs backup folder.



# counter #

This utility counts patterns in log files or in the lines received from stdin on a per interval basis.
The patterns and intervals are user defined but for both predefined defaults exists. By default the last 7
intervals are printed out. The interval is based on the slice of the timestamp, for example for a line
starting with a timestamp in "yyyymmdd:HHMMSS...." format using only the first 11 characters, "yyyymmdd:HH",
the intervall will be one HOUR. The pattern is a combination of a keyword, "event", and any accompaning string qualifiers. 

### Example ###

```
"DENYEVT,(event=\d+) (d1=\S+) (d2=\S+).*]"
```

specifies DENYEVT as event type and a group of potentially three components defined by a regular
expression. If input files are not provided the input is read from stdin.
Although it accepts any  regex expression to match pattern(s) in the input line it was mainly intended to analyze
Avaya Communication Manager ecs log files to count occurrences of alarms, errors, denial events, proc errors.

### Example ###

```
$ python counter.py -i HOUR --ecs=denial /var/log/ecs/2017-0427-0[456]*
DENYEVT       20170427:04  20170427:05  20170427:06  20170427:07
event=1012              1            2
event=1097                                        1
event=1189              1            5           48
event=1192             21           45            2
event=1220              2            1
event=1375              3            2           14
event=1378              4            7           57
event=1617                                        2
event=1644                                        6
event=1725              5            3            5
event=1934              6            6            6
event=1942                           5
event=2011                           3
event=2012                           1
event=2081              1            4
event=2094              2            4            4
event=2121                                        2
event=2176             40            6
event=2287             36          193          674            3
event=2292              1            2            2
```

Adding one or more -v displays one or more regex groups. For example one -v adds the (d1=\S+) group.
Also changing the interval to TMIN (ten minutes) and displaying only the last 3 intervals can further 
limits the scope of the interest.

### Example ###

```
$ python counter.py -v -i TMIN -n3 --ecs=denial /var/log/ecs/2017-0427-06*
DENYEVT                        20170427:064  20170427:065  20170427:070
event=1189 d1=830001                      1             1
event=1189 d1=830002                     11             9
event=1189 d1=830003                      1             2
event=1375 d1=7fc4                        1
event=1375 d1=98f4                                      2
event=1378 d1=6e95                                      1
event=1378 d1=7e24                        1
event=1378 d1=7e2c                                      1
event=1378 d1=7e2f                                      1
event=1378 d1=7e65                                      1
event=1378 d1=9957                        1
event=1644 d1=7881                                      1
event=1644 d1=8ce3                        2
event=1725 d1=86fe                        2
event=1725 d1=9977                        1
event=1934 d1=9bb9                                      1
event=1934 d1=9d0e                        1
event=2094 d1=10.191.172.88               1
event=2094 d1=10.191.172.89               1
event=2287 d1=0002                       99           193             3
event=2292 d1=abfac59                     1
```

And finally an example for a custom pattern.

### Example ###

```
python counter.py --timepos=0,6 -p "IPEVT,(reason=\w+)" /var/log/messages*
IPEVT                      Dec 12  Dec 28  Jan 11  Jan 14  Jan 30  Nov  8  Nov 28
reason=0                                1       6               2
reason=2010                     2
reason=2012                     2                       1
reason=endpoint_request         2       1       1       1                       4
reason=linkUp                                                           4       1
reason=normal                           1       6               1       6       6
reason=recovery                                 1
reason=switch_request                           8       1       1       6       2
reason=timeout                                  1       1
```



# extract #

Extracts MST messages from MTA decoded files when pattern(s) is/are in the MST message.
For example all MST messages with uid 9704 and 9b45:

### Example ###

```
python extract.py "9704|9b45" 1000_1100.m
```


#  serial_asai #

Serializes outbound ASAI DOMAIN messages from MST traces. It provides filtering capability to list only those 
outbound ASAI messages which match the link filter and/or callid, calling/called/connected number, trunk-channel
or ucid.

### Example ###

```
python serial_asai.py --link=4 --ucid 10000005931548338759 0905_0924.m
   Timestamp Link   Callids               Calling                Called                Connected          Trunks                                Event
09:06:04.785    4      0251             932688962                  2420                   421322         305/130  alerting |cv alertg evnt/call state
09:06:04.785    4      0251             932688962                  2420                   421322         305/130   connected (local answer detection)
09:06:05.166    4      0251                                                  ##### 421322 710192         305/130
09:06:05.167    4      0251             932688962                  2420                   710192         305/130   connected (local answer detection)
09:09:54.166    4 0251 0f25                421322                351104             ##### 710192         305/130                     call transferred
09:09:54.166    4 0251 0f25                421322                351104             ##### 710192         305/130                     call transferred
09:09:55.982    4      0f25             932688962                351104                   428370         305/130  alerting |cv alertg evnt/call state
09:09:55.984    4      0f25             932688962                351104                   428370         305/130   connected (local answer detection)
09:09:56.350    4      0f25                                                  ##### 428370 710004         305/130
09:09:56.350    4      0f25             932688962                351104                   710004         305/130   connected (local answer detection)
```



# sipstatCM #

This utility provides basic statistics on the number of SIP request methods and the corresponding responses found in
Avaya Communication Manager (ACM) version 6.x (and above) ecs log files. When run outside of an ACM server it can 
accept ecs log files as arguments to process them and generate statistics on. When used inside of an ACM server it can 
also monitor and parse those application log files realtime. Because of this second use case - when run in ACM shell
with no access to the external world and to repositories - it was developed to use only the built-in libraries 
(Python 2.4) that are available on ACM version 6.x and above.
Note: the MST in the ACM must be configured to write the SIP messages of at least one SIP signaling-group to the ecs log files. 

### Disclaimer ###

It renices itself to a low priority process and it is generally safe to use but it was not tested extensively on very
busy systemts in production environments and so use it at your own risk.

### Example ###

```
$ python sipstatCM.py /var/log/ecs/2017-0427-084*
20170427:0844                              INVITE   ReINVITE    BYE       500
                                          IN  OUT   IN  OUT   IN  OUT   IN  OUT
 10.1.1.1<-5070->10.2.2.2                  4    0    5   32    5    6    2    0

20170427:0845                              INVITE   ReINVITE    BYE       500
                                          IN  OUT   IN  OUT   IN  OUT   IN  OUT
 10.1.1.1<-5070->10.2.2.2                 10    0    0   23    4   10    2    0
```

### Or ###

```
$ python sipstatCM.py -n100 --request='INVITE|CANCEL|BYE' --responses='4|5|6' -i HOUR
20170427:07                                INVITE     BYE      CANCEL     487       503
                                          IN  OUT   IN  OUT   IN  OUT   IN  OUT   IN  OUT
 10.1.1.1<-5070->10.2.2.2                146    0   25  115    1    0    0    1    1    0
```
 


# trunc #

Truncate or append 0's to Call Record dump to match the size provided in the second argument, the optional third 
argument will specify the name of the output file, if not provided the input file name is appended with _trunc 
leaving the file extension intact. The purpose of this scrip is to work around the problems of MTA when it is
unable to decode the Call Records due to unexpected Call Record lenght.

### Example ###

```
python trunc.py 0710.M 708
```