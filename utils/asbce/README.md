# import_weblmca #

Running this script on an Avaya Session Border Controller for Enterprise allows you to imports the last
last certificate from a WebLM servers certificate chain into the SBCE's WebLM client keystore thus establishing a trust
relationship with the root CA certificate (last in chain) of the WebLM server and so the ASBCE can pull license from
that WebLM server provided there are available ASBCE licesense on it.

### Example ###
```
python import_weblmca.py --alias=new_weblm weblmserver.example.com:52233
```

# session_monitor #

Calculates the Peak or currently  Active sessions for the chosen interval 
from tracesbc_sip or SSYNDI files using the SIP messages only. The 
generated report may not be  100% accurate. Without input files provided 
as argument it parses one of the log file types mentioned above realtime. It 
updates the screen with the session counts only when the specified interval 
has ended  AND there was a change in session counts during that interval.

### Options ###

```
Options:
  -h, --help           show this help message and exit
  -a, --active         to show active session counts instead of peak at update
  -f                   to filter interface addresses, show session counts only
                       for these IP addresses, separeted by | (pipe)
  -i  , --interval=    to specify the sample interval, which can be SEC,
                       TENSEC, MIN, TENMIN, HOUR or DAY, the default is MIN
                       for realtime monitoring, otherwise HOUR
  -n num               to parse the last "n" number of hours of trace files
  -s, --ssyndi         to use SSYNDI instead of tracesbc_sip logs
  -t  , --timeframe=   to parse log files for the period specified by a
                       <start> and optional <end> date/time string as follows,
                       yyyymmdd[:HH[MM[SS]]][-yyyymmdd[:HH[MM[SS]]]]
                       for example: "20190308:0600-20190308:1800"
  -v, --verbose        to show session counts for each IP address of the
                       interfaces instead of grouping them together
```

```
$ python session_monitor.py -imin tracesbc_sip_1551306441_1551307399_1 -f "172.16.5.131|172.16.0.121|10.10.76.86"
Peak sessions     172.16.5.131    172.16.0.121    10.10.76.86        Total
                                      IN     OUT      IN     OUT
20190227:1831          0       1       0      19      19       0        39
20190227:1832          0       1       0      18      18       0        37
20190227:1833          0       1       1      16      16       1        35
20190227:1834          0       1       0      19      19       0        39
20190227:1835          0       0       0      27      27       0        54
20190227:1836          0       1       1      35      35       1        73
20190227:1837          0       1       1      37      37       1        77
20190227:1838          0       0       0      38      38       0        76
20190227:1839          0       0       0      39      39       0        78
20190227:1840          1       1       0      37      37       0        76
20190227:1841          0       1       0      37      37       0        75
20190227:1842          0       0       0      40      40       0        80
20190227:1843          0       0       0      37      37       0        74
```


# sipstatSBC #

This utility can parse trace logs of Avaya Communication Manager or Avaya
Session Border Controller for Enterprise for the purpose of providing a simply
summary of the number of SIP requests and responses seen on a per second, ten
seconds, minute, ten minutes or hourly basis. It parses CM "ecs" or SBCE
"tracesbc_sip" files. Without input log files it runs in monitor mode until a
user interrupt, CTRL^C, is received. It is assumed that MST was set up for at
least one SIP signaling-group and it is running in this mode. The type of SIP
methods and responses to monitor and count can be defined as arguments.


```
Options:
  -h, --help          show this help message and exit
  --requests=         SIP request types to monitor and count.
                      default: "INVITE|ReINVITE|BYE|CANCEL",
                      alternatively "ALL".
  --responses=        SIP response types to monitor and count.
                      default: "4|5|6", for example: "182|480|5",
                      only reponses for the DEFAULT_METHODS specified
                      in "--requests" or by its default will be counted.
  -i  , --interval=   sampling interval size, can be SEC, TENSEC, MIN, TENMIN
                      HOUR or DAY, default MIN,counters are zeroed at the end
                      of the interval.
  -n <number>         parse the last "n" number of tracesbc_sip files.
  -t <start>-<end>    start/end timestamps of the period to be processed,
                      in "YYYY[mmdd:HHMMSS]" format for example for example
                      "20170731:1630-20170731:1659" or "20170730-20170731"
  -v, --version       print version info.
```

```
$ python sipstatSBC.py ../../../../../VMs/tracesbc_sip_1551306441_1551307399_1 -iH --requests="BYE|INVITE"
20190227:18                                INVITE     BYE       403       407       487       491       500       504
                                          IN  OUT   IN  OUT   IN  OUT   IN  OUT   IN  OUT   IN  OUT   IN  OUT   IN  OUT
     10.32.76.86<-5060->10.32.75.9       111    5  106   22    0    0    0    0    1    0    0    0    1    0    0    0
     10.32.76.90<-5060->10.32.75.11       11   35   18   19    0    0    0    0    9    0    0    0    0    0    0    0
    172.27.0.121<-5060->172.27.0.100       5  111   22  106    0    0    0    0    0    1    0    2    0    1    0    0
    172.27.5.102<-5071->172.27.0.100      35   11   20   18    0    0    0    0    0    9    0    0    0    0    0    0
    172.27.5.122<-5083->172.27.0.100      46    7   38   10    0    0    0    0    0    2    0    0    0    0    0    0
    172.27.5.131<-5061->172.27.0.100       2   10    0    4    1    2    1    0    3    0    0    0    1    0    1    0
    172.27.5.146<-5060->24.50.205.147      0    2    0    0    2    0    0    0    0    0    0    0    0    0    0    0
    172.27.5.146<-5061->166.172.186.54    10    0    4    0    0    1    0    1    0    3    0    0    0    1    0    0
    172.29.15.58<-5060->172.29.2.11        7   46   10   38    0    0    0    0    2    0    0    0    0    0    0    0
```


# pycapSBC #

This utility can monitor SIP calls in Avaya Session Border Controller for Enterprise displaying
VoIP resource information of the caller and callee side in addition to other details. With a
simple button press it starts capturing the RTP and RTCP packets for a selected call or right
away when a call gets established for up to 2 (by default) simultaneous calls. It can also
show the RTP statistics, RTCP summary and any captured RFC2833 telephony events (DTMF payload)
for capture calls.

*Note: the current version works on ASBCE version 6.3, 7.0, 7.1 only. Work is in progress to
refactor, redesign and update this tool for newer ASBCE releases.

![alt text](./images/pycapSBC.jpg?raw=true "Dashboard")

![alt text](./images/pycapSBC2.jpg?raw=true "RTP stats")