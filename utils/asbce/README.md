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

