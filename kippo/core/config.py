# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import ConfigParser

def config():
    cfg = ConfigParser.ConfigParser()
    for f in ('kippo.cfg', '/etc/kippo/kippo.cfg', '/etc/kippo.cfg'):
        if os.path.exists(f):
            cfg.read(f)
            return cfg
    return None

# vim: set sw=4 et:
