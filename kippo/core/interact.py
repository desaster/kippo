from twisted.internet import protocol
from twisted.conch import telnet

class Interact(telnet.Telnet):

    def connectionMade(self):
        print 'Connected'
        self.interacting = None
        self.cmdbuf = ''
        self.honeypotFactory = self.factory.honeypotFactory

        # someone tell me if i'm doing this wrong?
        d = self.do(telnet.LINEMODE)
        self.requestNegotiation(telnet.LINEMODE, telnet.LINEMODE_EDIT + '\0')
        self.will(telnet.ECHO)

        self.transport.write('*** kippo session management console ***\r\n')
        self.cmd_help()

    def connectionLost(self, reason):
        print 'Connection lost'
        if self.interacting != None:
            self.interacting.delInteractor(self)

    def enableRemote(self, option):
        print 'enableRemote', repr(option)
        return option == telnet.LINEMODE
  
    def disableRemote(self, option):
        print 'disableRemote', repr(option)
  
    def applicationDataReceived(self, bytes):
        # in command mode, we want to echo characters and buffer the input
        if not self.interacting:
            self.transport.write(bytes)
            if bytes == '\r':
                self.transport.write('\n')
                pieces = self.cmdbuf.split(' ', 1)
                self.cmdbuf = ''
                cmd, args = pieces[0], ''
                if len(pieces) > 1:
                    args = pieces[1]
                try:
                    func = getattr(self, 'cmd_' + cmd)
                except AttributeError:
                    print 'Unknown command: %s' % (cmd,)
                    self.transport.write('** Unknown command.\r\n')
                    return
                func(args)
            else:
                self.cmdbuf += bytes

        # in non-command mode we are passing input to the session we are
        # watching
        else:
            for c in bytes:
                if ord(c) == 27: # escape
                    self.interacting.delInteractor(self)
                    self.interacting = None
                    self.transport.write(
                        '\r\n** Interactive session closed.\r\n')
                    return
            if not self.readonly:
                self.interacting.keystrokeReceived(bytes, None)

    def sessionWrite(self, data):
        buf, prev = '', ''
        for c in data:
            if c == '\n' and prev != '\r':
                buf += '\r\n'
            else:
                buf += c
            prev = c
        self.transport.write(buf)

    def sessionClosed(self):
        self.interacting.delInteractor(self)
        self.interacting = None
        self.transport.write('\r\n** Interactive session disconnected.\r\n')

    def cmd_hijack(self, args):
        self.cmd_view(args)
        self.readonly = False

    def cmd_view(self, args):
        self.readonly = True
        try:
            sessionno = int(args)
        except ValueError:
            self.transport.write('** Invalid session ID.\r\n')
            return
        for s in self.honeypotFactory.sessions:
            transport = s.terminal.transport.session.conn.transport
            if sessionno == transport.transport.sessionno:
                self.view(s)
                return
        self.transport.write('** No such session found.\r\n')

    def view(self, session):
        transport = session.terminal.transport.session.conn.transport
        sessionno = transport.transport.sessionno
        self.transport.write(
            '** Attaching to #%d, hit ESC to return\r\n' % sessionno)
        session.addInteractor(self)
        self.interacting = session

    def cmd_list(self, args):
        self.transport.write('ID   clientIP        clientVersion\r\n')
        for s in self.honeypotFactory.sessions:
            transport = s.terminal.transport.session.conn.transport
            sessionno = transport.transport.sessionno
            self.transport.write('%s %s %s\r\n' % \
                (str(sessionno).ljust(4),
                s.realClientIP.ljust(15),
                s.clientVersion))

    def cmd_help(self, args = ''):
        self.transport.write('List of commands:\r\n')
        self.transport.write(' list       - list all active sessions\r\n')
        self.transport.write(
            ' view       - attach to a session in read-only mode\r\n')
        self.transport.write(
            ' hijack     - attach to a session in interactive mode\r\n')
        self.transport.write(
            ' disconnect - disconnect a session\r\n')
        self.transport.write(' help       - this help\r\n')
        self.transport.write(' exit       - disconnect the console\r\n')

    def cmd_disconnect(self, args):
        try:
            sessionno = int(args)
        except ValueError:
            self.transport.write('** Invalid session ID.\r\n')
            return
        for s in self.honeypotFactory.sessions:
            transport = s.terminal.transport.session.conn.transport
            if sessionno == transport.transport.sessionno:
                self.transport.write(
                    '** Disconnecting session #%d\r\n' % sessionno)
                transport.loseConnection()
                return
        self.transport.write('** No such session found.\r\n')

    def cmd_exit(self, args = ''):
        self.transport.loseConnection()

def makeInteractFactory(honeypotFactory):
    ifactory = protocol.Factory()
    ifactory.protocol = Interact
    ifactory.honeypotFactory = honeypotFactory
    return ifactory

# vim: set sw=4 et: