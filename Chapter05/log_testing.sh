#!/bin/bash

for f in
{auth,authpriv,cron,daemon,kern,lpr,mail,mark,news,syslog,user,uucp,local0,local1,local2,local3,local4,local5,local6,local7}
do
for p in {debug,info,notice,warning,err,crit,alert,emerg}
do
logger -p $f.$p "Test syslog messages from facility $f with priority $p"
done
done