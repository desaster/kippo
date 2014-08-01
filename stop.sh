#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-
cd "$(readlink -m "$0"/..)" || exit $?

PIDFILE=kippo.pid
PID=$(LANG=C grep -xPe '[0-9]+' -m 1 "$PIDFILE" 2>/dev/null)

if [ -n "$PID" ]; then
  echo 'Stopping kippo...'
  kill -TERM "$PID"
fi
