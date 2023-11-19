import uuid

from wokkel import muc
from wokkel.xmppim import AvailablePresence


class XMPPLoggerProtocol(muc.MUCClient):

    def __init__(self, server, rooms, nick):
        muc.MUCClient.__init__(self)
        self.server = server
        self.jrooms = rooms
        self.nick = nick
        self.last = {}
        self.activity = None

    def initialized(self):
        """The bot has connected to the xmpp server, now try to join the room.
        """
        for i in self.jrooms:
            print(i)
            self.join(self.server, i, self.nick).addCallback(self.initRoom)

    def initRoom(self, room):
        print
        f'Joined room {room.name}'

    def connectionMade(self):
        print
        'Connected!'

        # send initial presence
        self.send(AvailablePresence())

    def connectionLost(self, reason):
        print
        'Disconnected!'

    def onMessage(self, msg):
        pass

    def receivedGroupChat(self, room, user, body):
        pass

    def receivedHistory(self, room, user, body, dely, frm=None):
        pass


from twisted.application import service
from twisted.words.protocols.jabber import jid
from wokkel.client import XMPPClient
from kippo.core import dblog
from twisted.words.xish import domish


class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        from random import choice
        import string

        server = cfg.get('database_xmpp', 'server')
        user = cfg.get('database_xmpp', 'user')
        password = cfg.get('database_xmpp', 'password')
        muc = cfg.get('database_xmpp', 'muc')
        channels = {}
        for i in ('createsession', 'connectionlost', 'loginfailed',
                  'loginsucceeded', 'command', 'clientversion'):
            x = cfg.get('database_xmpp', f'signal_{i}')
            if x not in channels:
                channels[x] = []
            channels[x].append(i)

        resource = ''.join([choice(string.ascii_letters) for _ in range(8)])
        jid = f'{user}/{resource}'
        application = service.Application('honeypot')
        self.run(application, jid, password, muc, channels)

    def run(self, application, jidstr, password, muc, channels, anon=True):
        self.xmppclient = XMPPClient(jid.internJID(jidstr), password)
        if self.cfg.has_option('database_xmpp', 'debug') and \
                self.cfg.get('database_xmpp', 'debug') in ('1', 'true', 'yes'):
            self.xmppclient.logTraffic = True  # DEBUG HERE
        (user, host, resource) = jid.parse(jidstr)
        self.muc = XMPPLoggerProtocol(muc, channels.keys(), f'{user}-{resource}')
        self.muc.setHandlerParent(self.xmppclient)
        self.xmppclient.setServiceParent(application)
        self.signals = {}
        for channel in channels:
            for signal in channels[channel]:
                self.signals[signal] = channel
        self.anonymous = True
        self.xmppclient.startService()

    def broadcast(self, msgtype, msg):
        if msgtype in self.signals:
            self.report(msgtype, f'{self.signals[msgtype]}@{self.muc.server}', msg)

    def report(self, msgtype, to, xmsg):
        body = domish.Element((None, 'body'))
        body.addContent('\n')
        msg = domish.Element(('http://code.google.com/p/kippo/', 'kippo'))
        msg['type'] = msgtype
        msg.addChild(xmsg)
        body.addChild(msg)
        self.muc.groupChat(to, None, children=[body])

    # We have to return an unique ID
    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        session = uuid.uuid4().hex
        ses = self.create_session_element(
            'session', session, peerIP, 'remote_host'
        )
        ses['remote_port'] = str(peerPort)
        ses['local_host'] = '127.0.0.1' if self.anonymous == True else hostIP
        ses['local_port'] = str(hostPort)

        self.broadcast('createsession', ses)
        return session

    def handleTTYLogOpened(self, session, args):
        pass

    def handleConnectionLost(self, session, args):
        ses = domish.Element((None, 'session'))
        ses['session'] = session
        self.broadcast('connectionlost', ses)

    def handleLoginFailed(self, session, args):
        self.create_and_broadcast_credentials(session, args, 'loginfailed')

    def handleLoginSucceeded(self, session, args):
        self.create_and_broadcast_credentials(session, args, 'loginsucceeded')

    def handleCommand(self, session, args):
        self.create_and_broadcast_command(session, 'known', args)

    def handleUnknownCommand(self, session, args):
        self.create_and_broadcast_command(session, 'unknown', args)

    def create_session_element(self, arg0, session, arg2, arg3):
        result = domish.Element((None, arg0))
        result['session'] = session
        result[arg3] = arg2
        return result

    def create_and_broadcast_command(self, session, arg1, args):
        ses = self.create_session_element(
            'command', session, arg1, 'command'
        )
        ses.addContent(args['input'])
        self.broadcast('command', ses)

    def create_and_broadcast_credentials(self, session, args, arg2):
        ses = self.create_element_with_attribute(
            'credentials', session, args, 'username'
        )
        ses['password'] = args['password']
        self.broadcast(arg2, ses)

    def handleTerminalSize(self, session, args):
        pass

    def handleInput(self, session, args):
        ses = self.create_element_with_attribute(
            'input', session, args, 'realm'
        )
        ses.addContent(args['input'])
        self.broadcast('input', ses)

    def create_element_with_attribute(self, arg0, session, args, arg3):
        result = domish.Element((None, arg0))
        result['session'] = session
        result[arg3] = args[arg3]
        return result

    def broadcast_client_version(self, session, args):
        ses = self.create_element_with_attribute(
            'version', session, args, 'version'
        )
        self.broadcast('clientversion', ses)

# vim: set sw=4 et:
