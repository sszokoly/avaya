# backup_ecs #

This script is supposed to be run in crontab and backs up the ecs logs files of Avaya Communication Manager
to a desired destination folder. The Avaya Communication Manager by default retains the last 1000 ecs log files.
A new ecs log file is created when the size of the file reaches 1MByte or every seconds. In a busy system when
MST trace is configured so that it generated and writes out lot of data to the ecs log files the worst case scenario
is that the system keeps only the last 1000 seconds worth of data which is often not enough. To keep a copy of a larger
set of ecs log files configure and use this script. There is always a partition on the system where plenty of 
disk space is available. You should edit this file with the desired parameters then add it to crontab (crontab -e)
to run it every 10 mins or less if need to, for example in crontab:

*/10 * * * * /usr/bin/python /var/home/admin/backup_ecs.py 

```
SRCDIR Specifies the source folder where the log files are backed up from.
       This is normally the /var/log/ecs folder where the ecs files are.
DSTDIR Specifies the destination folder where the log files are backed up to.
       This is by default the /var/home/ftp/pub/ecsbkp folder, which will be
       created if does not yet exist when the script runs.
FILES  Specifies the shell glob pattern of files to be backed up.
MAXUSE Determines the maximum %% of space that can be used up on the partition
       of the DSTDIR folder. The default is 90 percent.
GZIP   Determines if the backup is to be gzip compressed or not. The default
       is 1 which means it is.
RATIO  Gzip compression level, 9 slowest/most compression, 0 no compression.
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
 
