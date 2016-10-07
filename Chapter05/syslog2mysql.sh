# syslog2mysql script
#!/bin/bash

if [ -e /tmp/mysql.pipe ]; then
        while [ -e /tmp/mysql.pipe ]
                do
                        mysql -u syslog --password=syslog syslog < /tmp/mysql.pipe
        done
else
        mkfifo /tmp/mysql.pipe
fi