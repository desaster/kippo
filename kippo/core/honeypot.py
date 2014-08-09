# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import twisted
from twisted.cred import portal, checkers, credentials, error
from twisted.conch import avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, common, transport
from twisted.conch.insults import insults
from twisted.application import service, internet
from twisted.internet import reactor, protocol, defer
from twisted.python import failure, log
from zope.interface import implements
from copy import deepcopy, copy
import sys, os, random, pickle, time, stat, shlex, anydbm

from kippo.core import ttylog, fs, utils
from kippo.core.userdb import UserDB
from kippo.core.config import config
import commands

import ConfigParser

class HoneyPotCommand(object):
    def __init__(self, honeypot, *args):
        self.honeypot = honeypot
        self.args = args
        self.writeln = self.honeypot.writeln
        self.write = self.honeypot.terminal.write
        self.nextLine = self.honeypot.terminal.nextLine
        self.fs = self.honeypot.fs

    def start(self):
        self.call()
        self.exit()

    def call(self):
        self.honeypot.writeln('Hello World! [%s]' % repr(self.args))

    def exit(self):
        self.honeypot.cmdstack.pop()
        self.honeypot.cmdstack[-1].resume()

    def ctrl_c(self):
        print 'Received CTRL-C, exiting..'
        self.writeln('^C')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT: %s' % line

    def resume(self):
        pass

    def handle_TAB(self):
        pass

class HoneyPotShell(object):
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.showPrompt()
        self.cmdpending = []
        self.envvars = {
            'PATH':     '/bin:/usr/bin:/sbin:/usr/sbin',
            }

    def lineReceived(self, line):
        print 'CMD: %s' % line
        line = line[:500]
        for i in [x.strip() for x in line.strip().split(';')[:10]]:
            if not len(i):
                continue
            self.cmdpending.append(i)
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()

    def runCommand(self):
        def runOrPrompt():
            if len(self.cmdpending):
                self.runCommand()
            else:
                self.showPrompt()

        if not len(self.cmdpending):
            self.showPrompt()
            return
        line = self.cmdpending.pop(0)
        try:
            cmdAndArgs = shlex.split(line)
        except:
            self.honeypot.writeln(
                'bash: syntax error: unexpected end of file')
            # could run runCommand here, but i'll just clear the list instead
            self.cmdpending = []
            self.showPrompt()
            return

        # probably no reason to be this comprehensive for just PATH...
        envvars = copy(self.envvars)
        cmd = None
        while len(cmdAndArgs):
            piece = cmdAndArgs.pop(0)
            if piece.count('='):
                key, value = piece.split('=', 1)
                envvars[key] = value
                continue
            cmd = piece
            break
        args = cmdAndArgs

        if not cmd:
            runOrPrompt()
            return

        if len(args) > 0 and ('<' == args[-1] or '>' == args[-1] or '|' == args[-1]):
            print 'The attacker failed to a pipe command.'
            self.honeypot.logDispatch('The attacker failed to a pipe command.')

            if '<' == args[-1] or '>' == args[-1]:
                self.honeypot.writeln('bash: syntax error near unexpected token `newline\'')
            elif '|' == args[-1]:
                self.honeypot.writeln('bash: syntax error: unexpected end of file')
            self.cmdpending = []
            self.showPrompt()
            return

        i = 0
        for arg in args:
            i += 1
            if '<' == arg[-1:] or '>' == arg[-1:] or '|' == arg[-1:]:
                print 'The attacker is trying to a pipe command.'
                self.honeypot.logDispatch('The attacker is trying to a pipe command.')

                if '<' == arg[-1:]:
                    #path = args[i]
                    #if self.fs.exists(path):
                    #    continue
                    #else:
                    #    self.writeln('bash: no such file or directory: %s' % (path,))
                    self.honeypot.writeln('')
                    self.cmdpending = []
                    self.showPrompt()
                    return
                elif '>' == arg[-1:]:
                    self.cmdpending = []
                    self.showPrompt()
                    return
                elif '|' == arg[-1:]:
                    cmd = args[i]
                    args = args[i+1:]
                    print 'NEW CMD: %s' % cmd
                    print 'NEW ARGS: %s' % args

        rargs = []
        for arg in args:
            matches = self.honeypot.fs.resolve_path_wc(arg, self.honeypot.cwd)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.honeypot.getCommand(cmd, envvars['PATH'].split(':'))
        if cmdclass:
            print 'Command found: %s' % (line,)
            self.honeypot.logDispatch('Command found: %s' % (line,))
            self.honeypot.call_command(cmdclass, *rargs)
        else:
            self.honeypot.logDispatch('Command not found: %s' % (line,))
            print 'Command not found: %s' % (line,)
            if len(line):
                self.honeypot.writeln('bash: %s: command not found' % cmd)
                runOrPrompt()

    def resume(self):
        self.honeypot.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        # Example: nas3:~#
        #prompt = '%s:%%(path)s' % self.honeypot.hostname
        # Example: root@nas3:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.honeypot.user.username, self.honeypot.hostname,)
        # Example: [root@nas3 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.honeypot.user.username, self.honeypot.hostname,)
        if not self.honeypot.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        path = self.honeypot.cwd
        homelen = len(self.honeypot.user.home)
        if path == self.honeypot.user.home:
            path = '~'
        elif len(path) > (homelen+1) and \
                path[:(homelen+1)] == self.honeypot.user.home + '/':
            path = '~' + path[homelen:]
        # Uncomment the three lines below for a 'better' CenOS look.
        # Rather than '[root@nas3 /var/log]#' is shows '[root@nas3 log]#'.
        #path = path.rsplit('/', 1)[-1]
        #if not path:
        #    path = '/'

        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

    def ctrl_c(self):
        self.honeypot.lineBuffer = []
        self.honeypot.lineBufferIndex = 0
        self.honeypot.terminal.nextLine()
        self.showPrompt()

    # Tab completion
    def handle_TAB(self):
        if not len(self.honeypot.lineBuffer):
            return
        l = ''.join(self.honeypot.lineBuffer)
        if l[-1] == ' ':
            clue = ''
        else:
            clue = ''.join(self.honeypot.lineBuffer).split()[-1]
        try:
            basedir = os.path.dirname(clue)
        except:
            pass
        if len(basedir) and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not len(basedir):
            tmppath = self.honeypot.cwd
        try:
            r = self.honeypot.fs.resolve_path(tmppath, self.honeypot.cwd)
        except:
            return
        for x in self.honeypot.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if len(files) == 0:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.honeypot.lineBufferIndex):
            self.honeypot.terminal.cursorBackward()
            self.honeypot.terminal.deleteCharacter()

        newbuf = ''
        if len(files) == 1:
            newbuf = ' '.join(l.split()[:-1] + \
                ['%s%s' % (basedir, files[0][fs.A_NAME])])
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += '/'
            else:
                newbuf += ' '
        else:
            if len(os.path.basename(clue)):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ''
            first = l.split(' ')[:-1]
            newbuf = ' '.join(first + ['%s%s' % (basedir, prefix)])
            if newbuf == ''.join(self.honeypot.lineBuffer):
                self.honeypot.terminal.nextLine()
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.honeypot.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.honeypot.terminal.nextLine()
                    self.honeypot.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.honeypot.terminal.nextLine()
                self.showPrompt()

        self.honeypot.lineBuffer = list(newbuf)
        self.honeypot.lineBufferIndex = len(self.honeypot.lineBuffer)
        self.honeypot.terminal.write(newbuf)

class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, env):
        self.user = user
        self.env = env
        self.hostname = self.env.cfg.get('honeypot', 'hostname')
        self.fs = fs.HoneyPotFilesystem(deepcopy(self.env.fs))
        if self.fs.exists(user.home):
            self.cwd = user.home
        else:
            self.cwd = '/'
        # commands is also a copy so we can add stuff on the fly
        self.commands = copy(self.env.commands)
        self.password_input = False
        self.cmdstack = []

    def logDispatch(self, msg):
        transport = self.terminal.transport.session.conn.transport
        msg = ':dispatch: ' + msg
        transport.factory.logDispatch(transport.transport.sessionno, msg)

    def connectionMade(self):
        recvline.HistoricRecvLine.connectionMade(self)
        self.displayMOTD()
        self.cmdstack = [HoneyPotShell(self)]

        transport = self.terminal.transport.session.conn.transport
        transport.factory.sessions[transport.transport.sessionno] = self

        self.realClientIP = transport.transport.getPeer().host
        self.clientVersion = transport.otherVersionString
        self.logintime = transport.logintime
        self.ttylog_file = transport.ttylog_file

        # source IP of client in user visible reports (can be fake or real)
        cfg = config()
        if cfg.has_option('honeypot', 'fake_addr'):
            self.clientIP = cfg.get('honeypot', 'fake_addr')
        else:
            self.clientIP = self.realClientIP

        self.keyHandlers.update({
            '\x04':     self.handle_CTRL_D,
            '\x15':     self.handle_CTRL_U,
            '\x03':     self.handle_CTRL_C,
            '\x09':     self.handle_TAB,
            })

    def displayMOTD(self):
        try:
            self.writeln(self.fs.file_contents('/etc/motd'))
        except:
            pass

    # this doesn't seem to be called upon disconnect, so please use
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        recvline.HistoricRecvLine.connectionLost(self, reason)

        # not sure why i need to do this:
        # scratch that, these don't seem to be necessary anymore:
        #del self.fs
        #del self.commands

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def txtcmd(self, txt):
        class command_txtcmd(HoneyPotCommand):
            def call(self):
                print 'Reading txtcmd from "%s"' % txt
                f = file(txt, 'r')
                self.write(f.read())
                f.close()
        return command_txtcmd

    def getCommand(self, cmd, paths):
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in ('.', '/'):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in ['%s/%s' % (self.fs.resolve_path(x, self.cwd), cmd) \
                    for x in paths]:
                if self.fs.exists(i):
                    path = i
                    break
        txt = os.path.abspath('%s/%s' % \
            (self.env.cfg.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)
        if path in self.commands:
            return self.commands[path]
        return None

    def lineReceived(self, line):
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def keystrokeReceived(self, keyID, modifier):
        transport = self.terminal.transport.session.conn.transport
        if type(keyID) == type(''):
            ttylog.ttylog_write(transport.ttylog_file, len(keyID),
                ttylog.TYPE_INPUT, time.time(), keyID)
        recvline.HistoricRecvLine.keystrokeReceived(self, keyID, modifier)

    # Easier way to implement password input?
    def characterReceived(self, ch, moreCharactersComing):
        if self.mode == 'insert':
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex:self.lineBufferIndex+1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)

    def writeln(self, data):
        self.terminal.write(data)
        self.terminal.nextLine()

    def call_command(self, cmd, *args):
        obj = cmd(self, *args)
        self.cmdstack.append(obj)
        self.setTypeoverMode()
        obj.start()

    def handle_RETURN(self):
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self):
        self.cmdstack[-1].ctrl_c()

    def handle_CTRL_U(self):
        for i in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
        self.lineBufferIndex = 0

    def handle_CTRL_D(self):
        self.call_command(self.commands['exit'])

    def handle_TAB(self):
        self.cmdstack[-1].handle_TAB()

    def addInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.append(interactor)

    def delInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.remove(interactor)

    def uptime(self, reset = None):
        transport = self.terminal.transport.session.conn.transport
        r = time.time() - transport.factory.starttime
        if reset:
            transport.factory.starttime = reset
        return r

class LoggingServerProtocol(insults.ServerProtocol):
    def connectionMade(self):
        transport = self.transport.session.conn.transport

        transport.ttylog_file = '%s/tty/%s-%s.log' % \
            (config().get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'),
            int(random.random() * 10000))
        print 'Opening TTY log: %s' % transport.ttylog_file
        ttylog.ttylog_open(transport.ttylog_file, time.time())

        transport.ttylog_open = True

        insults.ServerProtocol.connectionMade(self)

    def write(self, bytes, noLog = False):
        transport = self.transport.session.conn.transport
        for i in transport.interactors:
            i.sessionWrite(bytes)
        if transport.ttylog_open and not noLog:
            ttylog.ttylog_write(transport.ttylog_file, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)
        insults.ServerProtocol.write(self, bytes)

    # this doesn't seem to be called upon disconnect, so please use
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        insults.ServerProtocol.connectionLost(self, reason)

class HoneyPotSSHSession(session.SSHSession):
    def request_env(self, data):
        print 'request_env: %s' % (repr(data))

class HoneyPotAvatar(avatar.ConchUser):
    implements(conchinterfaces.ISession)

    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.channelLookup.update({'session': HoneyPotSSHSession})

        userdb = UserDB()
        self.uid = self.gid = userdb.getUID(self.username)

        if not self.uid:
            self.home = '/root'
        else:
            self.home = '/home/' + username

    def openShell(self, protocol):
        serverProtocol = LoggingServerProtocol(HoneyPotProtocol, self, self.env)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        print 'Terminal size: %s %s' % windowSize[0:2]
        self.windowSize = windowSize
        return None

    def execCommand(self, protocol, cmd):
        raise NotImplementedError

    def closed(self):
        pass

    def eofReceived(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize

class HoneyPotEnvironment(object):
    def __init__(self):
        self.cfg = config()
        self.commands = {}
        import kippo.commands
        for c in kippo.commands.__all__:
            module = __import__('kippo.commands.%s' % c,
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)
        self.fs = pickle.load(file(
            self.cfg.get('honeypot', 'filesystem_file'), 'rb'))

class HoneyPotRealm:
    implements(portal.IRealm)

    def __init__(self):
        # I don't know if i'm supposed to keep static stuff here
        self.env = HoneyPotEnvironment()

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception, "No supported interfaces found."

class HoneyPotTransport(transport.SSHServerTransport):

    hadVersion = False

    def connectionMade(self):
        print 'New connection: %s:%s (%s:%s) [session: %d]' % \
            (self.transport.getPeer().host, self.transport.getPeer().port,
            self.transport.getHost().host, self.transport.getHost().port,
            self.transport.sessionno)
        self.interactors = []
        self.logintime = time.time()
        self.ttylog_open = False
        transport.SSHServerTransport.connectionMade(self)

    def sendKexInit(self):
        # Don't send key exchange prematurely
        if not self.gotVersion:
            return
        transport.SSHServerTransport.sendKexInit(self)

    def dataReceived(self, data):
        transport.SSHServerTransport.dataReceived(self, data)
        # later versions seem to call sendKexInit again on their own
        if twisted.version.major < 11 and \
                not self.hadVersion and self.gotVersion:
            self.sendKexInit()
            self.hadVersion = True

    def ssh_KEXINIT(self, packet):
        print 'Remote SSH version: %s' % (self.otherVersionString,)
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def lastlogExit(self):
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = utils.durationHuman(time.time() - self.logintime)
        clientIP = self.transport.getPeer().host
        utils.addToLastlog('root\tpts/0\t%s\t%s - %s (%s)' % \
            (clientIP, starttime, endtime, duration))

    # this seems to be the only reliable place of catching lost connection
    def connectionLost(self, reason):
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        self.lastlogExit()
        if self.ttylog_open:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False
        transport.SSHServerTransport.connectionLost(self, reason)

    def sendDisconnect(self, reason, desc):
        """
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg('Disconnecting with error, code %s\nreason: %s' % (reason, desc))
            self.transport.loseConnection()

from twisted.conch.ssh.common import NS, getNS
class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        cfg = config()
        if not cfg.has_option('honeypot', 'banner_file'):
            return
        try:
            data = file(cfg.get('honeypot', 'banner_file')).read()
        except IOError:
            print 'Banner file %s does not exist!' % \
                cfg.get('honeypot', 'banner_file')
            return
        if not data or not len(data.strip()):
            return
        data = '\r\n'.join(data.splitlines() + [''])
        self.transport.sendPacket(
            userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))
        self.bannerSent = True

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

# As implemented by Kojoney
class HoneyPotSSHFactory(factory.SSHFactory):
    services = {
        'ssh-userauth': HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.SSHConnection,
        }

    # Special delivery to the loggers to avoid scope problems
    def logDispatch(self, sessionid, msg):
        for dblog in self.dbloggers:
            dblog.logDispatch(sessionid, msg)

    def __init__(self):
        cfg = config()

        # protocol^Wwhatever instances are kept here for the interact feature
        self.sessions = {}

        # for use by the uptime command
        self.starttime = time.time()

        # convert old pass.db root passwords
        passdb_file = '%s/pass.db' % (cfg.get('honeypot', 'data_path'),)
        if os.path.exists(passdb_file):
            userdb = UserDB()
            print 'pass.db deprecated - copying passwords over to userdb.txt'
            if os.path.exists('%s.bak' % (passdb_file,)):
                print 'ERROR: %s.bak already exists, skipping conversion!' % \
                    (passdb_file,)
            else:
                passdb = anydbm.open(passdb_file, 'c')
                for p in passdb:
                    userdb.adduser('root', 0, p)
                passdb.close()
                os.rename(passdb_file, '%s.bak' % (passdb_file,))
                print 'pass.db backed up to %s.bak' % (passdb_file,)

        # load db loggers
        self.dbloggers = []
        for x in cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            dbengine = 'database_' + engine
            lcfg = ConfigParser.ConfigParser()
            lcfg.add_section(dbengine)
            for i in cfg.options(x):
                lcfg.set(dbengine, i, cfg.get(x, i))
            lcfg.add_section('honeypot')
            for i in cfg.options('honeypot'):
                lcfg.set('honeypot', i, cfg.get('honeypot', i))
            print 'Loading dblog engine: %s' % (engine,)
            dblogger = __import__(
                'kippo.dblog.%s' % (engine,),
                globals(), locals(), ['dblog']).DBLogger(lcfg)
            log.startLoggingWithObserver(dblogger.emit, setStdout=False)
            self.dbloggers.append(dblogger)

    def buildProtocol(self, addr):
        cfg = config()

        # FIXME: try to mimic something real 100%
        t = HoneyPotTransport()

        if cfg.has_option('honeypot', 'ssh_version_string'):
            t.ourVersionString = cfg.get('honeypot','ssh_version_string')
        else:
            t.ourVersionString = "SSH-2.0-OpenSSH_5.1p1 Debian-5"

        t.supportedPublicKeys = self.privateKeys.keys()

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        t.factory = self
        return t

class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,
        credentials.IPluggableAuthenticationModules)

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(error.UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                credentials.pamConversion)
        return defer.fail(error.UnhandledCredentials())

    def checkPamUser(self, username, pamConversion):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username)

    def cbCheckPamUser(self, responses, username):
        for response, zero in responses:
            if self.checkUserPass(username, response):
                return defer.succeed(username)
        return defer.fail(error.UnauthorizedLogin())

    def checkUserPass(self, username, password):
        if UserDB().checklogin(username, password):
            print 'login attempt [%s/%s] succeeded' % (username, password)
            return True
        else:
            print 'login attempt [%s/%s] failed' % (username, password)
            return False

def getRSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'rsa_public_key')
    private_key = cfg.get('honeypot', 'rsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new RSA keypair..."
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = keys.Key(rsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
        print "Done."
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

def getDSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'dsa_public_key')
    private_key = cfg.get('honeypot', 'dsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new DSA keypair..."
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = keys.Key(dsaKey).toString('openssh')
        with file(public_key, 'w+b') as f:
            f.write(publicKeyString)
        with file(private_key, 'w+b') as f:
            f.write(privateKeyString)
        print "Done."
    else:
        with file(public_key) as f:
            publicKeyString = f.read()
        with file(private_key) as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

# vim: set sw=4 et:
