#!/bin/bash
# -*- coding: utf-8, tab-width: 2 -*-
cd "$(dirname "$0")" || exit $?
tty --silent && echo 'Starting kippo in the background...'
twistd -y kippo.tac -l log/kippo.log --pidfile kippo.pid
