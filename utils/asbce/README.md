# import_weblmca #

Running this script on an Avaya Session Border Controller for Enterprise allows you to imports the last
last certificate from a WebLM servers certificate chain into the SBCE's WebLM client keystore thus establishing a trust
relationship with the root CA certificate (last in chain) of the WebLM server and so the ASBCE can pull license from
that WebLM server provided there are available ASBCE licesense on it.

### Example ###
```
python import_weblmca.py --alias=new_weblm weblmserver.example.com:52233
```


# max_sessions #

Calculates the maximum concurrent session counts per interval from the ASBCE tracesbc_sip files.

### Options ###
```
  -i  , --interval=    specifies the sample interval, which can be SEC,
                       TENSEC, MIN, TENMIN HOUR or DAY, the default is HOUR.
  -t  , --timeframe=   parses the tracesbc_sip logs for this period.
                       the format is YYYYmmdd:HHMM-[YYYYmmdd:HHMM]
                       example: "20171108:1600-20171108:1800"
```
                    
### Example ###
```
python max_sessions.py /archive/log/tracesbc/tracesbc_sip_1510*
```

Or if you want to see the session_counts for a specific period, here between
2019-02-10 08:00 and 2019-02-10 18:00 then use the -t option.

### Example ###
```
python max_sessions.py -t "20190210:0800-20190210:1800"
```

### Note ###

The generated report may not be 100% accurate always due to the fact that logging may be halted 
temporarily from time to time on a very  busy system, call processing normally continues unaffected though.



# pyppm #

This tool parses ASBCE PPM log file, tracesbc_ppm, displays the content in a somewhat prettyfied format.
In addition it provides filtering capabilities.

### Options ###

```
  -u <handle>  to filter messages related to the given user handle only, for
               example for user handle "1021@example.com" use "-u 1021"
  -t           terse output, prints only a summary line per message
  -a, --all    to print all messages, by default only endpoint messages are
               printed, that is Endpoint <-> SBC Public interface.
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
$ python session_monitor.py -imin tracesbc_sip_1551306441_1551307399_1 -f "172.27.5.131|172.27.0.121|10.32.76.86"
Peak sessions     172.27.5.131    172.27.0.121    10.32.76.86        Total
                                      IN     OUT      IN     OUT
20190227:1827                          0       1       1       0         2
20190227:1828                          0       4       4       0         8
20190227:1829                          0       9       9       0        18
20190227:1830                          0      17      17       0        34
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
