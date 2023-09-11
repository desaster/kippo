#!/bin/bash
# Send alerts when the honeypot is breached, including attacker activity details...
# greg.foss[at]owasp.org
# v0.1 - 1/6/2015

file=$(ls /opt/kippo/log/tty/*.log | cut -d"/" -f 6)
filecount=$(ls /opt/kippo/log/tty/*.log | wc -l)
host=$(ifconfig | grep 'inet addr' | grep -v '127' | cut -d":" -f2 | awk '{print $1}')
hostname=$(hostname)

if [ $filecount -gt 0 ]
then
	for i in $file; do
		python /opt/kippo/utils/playlog.py /opt/kippo/log/tty/$i -m 1 > /opt/kippo/log/played/$i
		mv /opt/kippo/log/tty/$i /opt/kippo/log/tty/old/
		unix2dos -f /opt/kippo/log/played/$i
		sendEmail -f [FROM@ADDRESS.COM] -t [TO@ADDRESS.COM] -u "Kippo Honeypot Breached" -m "A Kippo Honeypot [$hostname] located at [$host] has been breached. A log of the attacker's activities has been attached for review" -a /opt/kippo/log/played/$i -s [YOUR.MAIL.SERVER]:25 -o tls=no
	done;
else
	exit
fi
