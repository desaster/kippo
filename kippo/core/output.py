# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import abc
import datetime
import re
import copy
import socket
import uuid

# KIPP0001 : create session
# KIPP0002 : succesful login
# KIPP0003 : failed login
# KIPP0004 : TTY log opened
# KIPP0005 : handle command
# KIPP0006 : handle unknown command
# KIPP0007 : file download
# KIPP0008 : INPUT
# KIPP0009 : SSH Version
# KIPP0010 : Terminal Size
# KIPP0011 : Connection Lost
# KIPP0012 : TTY log closed
# KIPP0013 : env var requested

class Output(object):
    """
    This is the abstract base class intended to be inherited by kippo output plugins
    Plugins require the mandatory methods: stop, start and write
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ips = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')
        if self.cfg.has_option('honeypot', 'sensor_name'):
            self.sensor = self.cfg.get('honeypot', 'sensor_name')
        else:
            self.sensor = socket.gethostname()

        self.start()

    # use logDispatch when the HoneypotTransport prefix is not available.
    # here you can explicitly set the sessionIds to tie the sessions together
    #def logDispatch(self, sessionid, msg):
    #    if isinstance( msg, dict ):
    #        msg['sessionid'] = sessionid
    #        return self.emit( msg )
    #    elif isinstance( msg, str ):
    #        return self.emit( { 'message':msg, 'sessionid':sessionid } )
    def logDispatch(self, *msg, **kw):
        ev = kw
        ev['message'] = msg
        self.emit(ev)

    @abc.abstractmethod
    def start(self):
        """Abstract method to initialize output plugin"""
        pass

    @abc.abstractmethod
    def stop(self):
        """Abstract method to shut down output plugin"""
        pass

    @abc.abstractmethod
    def write(self, event):
        """Handle a general event within the output plugin"""
        pass

    # this is the main emit() hook that gets called by the the Twisted logging
    def emit(self, event):
        # ignore stdout and stderr in output plugins
        if 'printed' in event:
            return

        # ignore anything without eventid
        if not 'eventid' in event:
            return

        ev = copy.copy(event)

        if 'isError' in ev:
            del ev['isError']
        ev['sensor'] = self.sensor

        # add ISO timestamp and sensor data
        if not 'time' in ev:
            ev['timestamp'] = datetime.datetime.today().isoformat() + 'Z'
        else:
            ev['timestamp'] = datetime.datetime.fromtimestamp(ev['time']).isoformat() + 'Z'
            del ev['time']

        # on disconnect, add the tty log
        #if ev['eventid'] == 'KIPP0012':
            # FIXME: file is read for each output plugin
            #f = file(ev['ttylog'])
            #ev['ttylog'] = f.read(10485760)
            #f.close()
            #pass

        # explicit sessionno (from logDispatch) overrides from 'system'
        if 'sessionno' in ev:
            sessionno = ev['sessionno']
            del ev['sessionno']
        # extract session id from the twisted log prefix
        elif 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionno = int(match.groups()[0])
            del ev['system']

        if sessionno in self.ips:
            ev['src_ip'] = self.ips[sessionno]

        # connection event is special. adds to session list
        if ev['eventid'] == 'KIPP0001':
            self.sessions[sessionno] = uuid.uuid4().hex
            self.ips[sessionno] = ev['src_ip']
            del ev['system']

        ev['session'] = self.sessions[sessionno]

        self.write(ev)

        # disconnect is special, remove cached data
        if ev['eventid'] == 'KIPP0011':
            del self.sessions[sessionno]
            del self.ips[sessionno]

# vim: set sw=4 et:
