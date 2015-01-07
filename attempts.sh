#!/bin/bash
# Basic dashboard to show recent honeypot stats...
# greg.foss[at]owasp.org
# v0.1 - 1/6/2015

echo ""
echo "reviewing logs -- this may take some time, please be patient..."
echo ""

# queries
search=$(find /opt/kippo/log/kippo.log*)
attackers=$(echo "$search" | xargs -n16 -P18 grep -iH 'login attempt' | cut -d "]" -f 1 | cut -d "," -f 3 | uniq);
breaches=$(echo "$search" | xargs -n16 -P18 grep -iH 'cmd' | cut -d "," -f 3 | cut -d "]" -f 1 | uniq);
files=$(echo "$search" | xargs -n16 -P18 grep -iH "http:" | cut -d"]" -f 2 | awk '{print $3}' | grep -v '^$\|wget\|<\|(\|)' | uniq);
attempts=$(echo "$search" | xargs -n16 -P18 grep -iH 'login attempt' | cut -d "]" -f 2,3 | cut -d" " -f 4);

# counts
success=$(echo "$attempts" | grep '\[USERNAME1/PASSWORD1\]\|\[USERNAME2/PASSWORD2\]' | wc -l);
attackercount=$(echo "$attackers" sort -u | wc -l)
attemptcount=$(echo "$attempts" | wc -l);
breachcount=$(echo "$breaches" | wc -l)
filecount=$(echo "$files" | wc -l)

clear
echo ""
echo "Kippo Honeypot Statistics"
echo ""
echo $success" => successful password guesses"
echo $attemptcount" => total login attempts"
echo $attackercount" => total attacking IPs (10 most recent entries below)"
echo "--------------------"
echo "$attackers" | tail -n 10
echo "--------------------"
echo ""
echo $breachcount" => honeypot breaches (10 most recent entries below)"
echo "--------------------"
echo "$breaches" | uniq | tail -n 10
echo "--------------------"
echo ""
echo $filecount" => payloads downloaded (10 most recent entries below)"
echo "--------------------"
echo "$files" | tail -n 10
echo "--------------------"
echo ""