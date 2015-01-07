#!/bin/bash
# RUN AS ROOT
# Set iptables to forward to the [default] kippo port

iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222