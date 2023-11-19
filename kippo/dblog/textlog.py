#
# this module uses the dblog feature to create a "traditional" looking logfile
# ..so not exactly a dblog.
#

import time
import uuid

from kippo.core import dblog


class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.outfile = file(cfg.get('database_textlog', 'logfile'), 'a')

    def write(self, session, msg):
        self.outfile.write('%s [%s]: %s\r\n' % \
                           (session, time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        self.outfile.flush()

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex
        sensorname = self.getSensor() or hostIP
        self.write(sid, f'New connection: {peerIP}:{peerPort}')
        return sid

    def handleConnectionLost(self, session, args):
        self.write(session, 'Connection lost')

    def handleLoginFailed(self, session, args):
        self.write(session, f"Login failed [{args['username']}/{args['password']}]")

    def handleLoginSucceeded(self, session, args):
        self.write(session, f"Login succeeded [{args['username']}/{args['password']}]")

    def handleCommand(self, session, args):
        self.write(session, f"Command [{args['input']}]")

    def handleUnknownCommand(self, session, args):
        self.write(session, f"Unknown command [{args['input']}]")

    def handleInput(self, session, args):
        self.write(session, f"Input [{args['input']}] @{args['realm']}")

    def handleTerminalSize(self, session, args):
        self.write(session, f"Terminal size: {args['width']}x{args['height']}")

    def broadcast_client_version(self, session, args):
        self.write(session, f"Client version: [{args['version']}]")

    def handleFileDownload(self, session, args):
        self.write(session, f"File download: [{args['url']}] -> {args['outfile']}")

# vim: set sw=4 et:
