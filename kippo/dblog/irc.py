from kippo.core import dblog
from asyncirc.ircbot import IRCBot
import uuid

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        if cfg.has_option('database_irc', 'port'):
            port = int(cfg.get('database_irc', 'port'))
        else:
            port = 6667

        nick = self.getSensor()
        if cfg.has_option('database_irc', 'nick'):
            nick = cfg.get('database_irc', 'nick')
        if nick is None:
            import random
            import string
            nick = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))

        self.channels = ['kippo-events']
        if cfg.has_option('database_irc', 'channel'):
            self.channels = cfg.get('database_irc', 'channel').split(",")

        server = 'irc.efnet.org'
        if cfg.has_option('database_irc', 'server'):
            server = cfg.get('database_irc', 'server')

        password = None
        if cfg.has_option('database_irc', 'password'):
            password = cfg.get('database_irc', 'password')

        self.connection = IRCBot(server, port, nick, nick, 'Kippo', password)
        self.connection.start()
        for channel in self.channels:
            self.connection.join(channel)

    def write(self, session, message):
        if self.connection:
            for channel in self.channels:
                self.connection.msg(channel, "[%s] %s" % (session, message))

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex
        self.write(sid, 'New connection: %s:%s' % (peerIP, peerPort))
        return sid

    def handleConnectionLost(self, session, args):
        self.write(session, 'Connection lost')

    def handleLoginFailed(self, session, args):
        self.write(session, 'Login failed [%s/%s]' % \
            (args['username'], args['password']))

    def handleLoginSucceeded(self, session, args):
        self.write(session, 'Login succeeded [%s/%s]' % \
            (args['username'], args['password']))

    def handleCommand(self, session, args):
        self.write(session, 'Command [%s]' % (args['input'],))

    def handleUnknownCommand(self, session, args):
        self.write(session, 'Unknown command [%s]' % (args['input'],))

    def handleInput(self, session, args):
        self.write(session, 'Input [%s] @%s' % (args['input'], args['realm']))

    def handleTerminalSize(self, session, args):
        self.write(session, 'Terminal size: %sx%s' % \
            (args['width'], args['height']))

    def handleClientVersion(self, session, args):
        self.write(session, 'Client version: [%s]' % (args['version'],))

    def handleFileDownload(self, session, args):
        self.write(session, 'File download: [%s] -> %s' % \
            (args['url'], args['outfile']))
# vim: set sw=4 et:
