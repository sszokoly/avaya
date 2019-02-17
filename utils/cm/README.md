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
 
