# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os, time, anydbm, datetime
from kippo.core.honeypot import HoneyPotCommand
from twisted.internet import reactor
from kippo.core.config import config
from kippo.core.auth import UserDB
from kippo.core import utils

commands = {}

class command_whoami(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.user.username)
commands['/usr/bin/whoami'] = command_whoami

class command_uptime(HoneyPotCommand):
    def call(self):
        if len(self.args):
            secs = int(self.args[0])
            self.honeypot.uptime(time.time() - secs)
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.honeypot.uptime())))
commands['/usr/bin/uptime'] = command_uptime

class command_w(HoneyPotCommand):
    def call(self):
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.honeypot.uptime())))
        self.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')
        self.writeln('%-8s pts/0    %s %s    0.00s  0.00s  0.00s w' % \
            (self.honeypot.user.username,
            self.honeypot.clientIP[:17].ljust(17),
            time.strftime('%H:%M', time.localtime(self.honeypot.logintime))))
commands['/usr/bin/w'] = command_w
commands['/usr/bin/who'] = command_w

class command_echo(HoneyPotCommand):
    def call(self):
        self.writeln(' '.join(self.args))
commands['/bin/echo'] = command_echo

# for testing purposes
class command_exxxit(HoneyPotCommand):
    def call(self):
        if self.honeypot.clientIP.startswith('127.0.0.'):
            self.honeypot.terminal.loseConnection()
        else:
            self.writeln('bash: exxxit: command not found')
commands['exxxit'] = command_exxxit

class command_exit(HoneyPotCommand):
    def call(self):
        if 'PuTTY' in self.honeypot.clientVersion or \
                'libssh' in self.honeypot.clientVersion or \
                'sshlib' in self.honeypot.clientVersion:
            self.honeypot.terminal.loseConnection()
            return
        self.honeypot.terminal.reset()
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
commands['exit'] = command_exit
commands['logout'] = command_exit

class command_clear(HoneyPotCommand):
    def call(self):
        self.honeypot.terminal.reset()
commands['/usr/bin/clear'] = command_clear

class command_hostname(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.hostname)
commands['/bin/hostname'] = command_hostname

class command_uname(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() in ('-a', '--all'):
            self.writeln(
                'Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686 GNU/Linux' % \
                self.honeypot.hostname)
        else:
            self.writeln('Linux')
commands['/bin/uname'] = command_uname

class command_ps(HoneyPotCommand):
    def call(self):
        user = self.honeypot.user.username
        args = ''
        if len(self.args):
            args = self.args[0].strip()
        _user, _uid, _pid, _ppid, _cpu, _mem, _vsz, _rss, \
            _tty, _stat, _c, _start, _time, _command = range(14)
        output = (
            ('USER      ','UID       ', ' PID', ' PPID' , ' %CPU', ' %MEM', '    VSZ', '   RSS', ' TTY      ', 'STAT ', ' C ', ' START ', '   TIME ', 'COMMAND',),
            ('root      ','root      ', '   1', '    0' , '  0.0', '  0.1', '   2100', '   688', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:09 ', 'init [2]  ',),
            ('root      ','root      ', '   2', '    0' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kthreadd]',),
            ('root      ','root      ', '   3', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[ksoftirqd/0]',),
            ('root      ','root      ', '   5', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kworker/u:0]',),
            ('root      ','root      ', '   6', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[migration/0]',),
            ('root      ','root      ', '   7', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[watchdog/0]',),
            ('root      ','root      ', '   8', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[migration/1]',),
            ('root      ','root      ', '   9', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kworker/1:0]',),
            ('root      ','root      ', '  10', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[ksoftirqd/1]',),
            ('root      ','root      ', '  12', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[watchdog/0]',),
            ('root      ','root      ', '  13', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[khelper]',),
            ('root      ','root      ', '  14', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kdevtmpfs]',),
            ('root      ','root      ', '  15', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[cpuset/0]',),
            ('root      ','root      ', '  20', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:17 ', '[events/0]',),
            ('root      ','root      ', '  23', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kblockd/0]',),
            ('root      ','root      ', '  24', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kacpid]',),
            ('root      ','root      ', '  25', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kacpi_notify]',),
            ('root      ','root      ', ' 100', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kseriod]',),
            ('root      ','root      ', ' 107', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S    ', ' 0 ', ' May20 ', '   0:01 ', '[pdflush]',),
            ('root      ','root      ', ' 108', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S    ', ' 0 ', ' May20 ', '   0:00 ', '[pdflush]',),
            ('root      ','root      ', ' 109', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kswapd0]',),
            ('root      ','root      ', ' 110', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[aio/0]',),
            ('root      ','root      ', ' 348', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[ata/0]',),
            ('root      ','root      ', ' 349', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[ata_aux]',),
            ('root      ','root      ', ' 629', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[scsi_eh_0]',),
            ('root      ','root      ', ' 707', '    2' , '  0.0', '  0.1', '   2290', '  1308', ' ?        ', 'S<s  ', ' 0 ', ' May20 ', '   0:00 ', 'udevd --daemon',),
            ('root      ','root      ', '1014', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'D<   ', ' 0 ', ' May20 ', '   0:03 ', '[kjournald]',),
            ('root      ','root      ', '1087', '  707' , '  0.0', '  0.1', '   2288', '  1016', ' ?        ', 'S<s  ', ' 0 ', ' May20 ', '   0:00 ', 'udevd --daemon',),
            ('root      ','root      ', '1087', '  707' , '  0.0', '  0.1', '   2288', '   952', ' ?        ', 'S<s  ', ' 0 ', ' May20 ', '   0:00 ', 'udevd --daemon',),
            ('root      ','root      ', '1553', '    2' , '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', ' 0 ', ' May20 ', '   0:00 ', '[kpsmoused]',),
            ('root      ','root      ', '2054', '    2' , '  0.0', '  0.2', '  28428', '  1508', ' ?        ', 'Sl   ', ' 0 ', ' May20 ', '   0:01 ', '/usr/sbin/rsyslogd -c3',),
            ('root      ','root      ', '2103', '    2' , '  0.0', '  0.2', '   2628', '  1196', ' tty1     ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '/bin/login --     ',),
            ('root      ','root      ', '2105', '    2' , '  0.0', '  0.0', '   1764', '   504', ' tty2     ', 'Ss+  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/getty 38400 tty2',),
            ('root      ','root      ', '2107', '    2' , '  0.0', '  0.0', '   1764', '   504', ' tty3     ', 'Ss+  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/getty 38400 tty3',),
            ('root      ','root      ', '2109', '    2' , '  0.0', '  0.0', '   1764', '   504', ' tty4     ', 'Ss+  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/getty 38400 tty4',),
            ('root      ','root      ', '2110', '    2' , '  0.0', '  0.0', '   1764', '   504', ' tty5     ', 'Ss+  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/getty 38400 tty5',),
            ('root      ','root      ', '2112', '    2' , '  0.0', '  0.0', '   1764', '   508', ' tty6     ', 'Ss+  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/getty 38400 tty6',),
            ('root      ','root      ', '2133', '    2' , '  0.0', '  0.1', '   2380', '   620', ' ?        ', 'S<s  ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/rpcbind -w',),
            ('root      ','root      ', '2145', '    2' , '  0.0', '  0.1', '   2180', '  1876', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', 'dhclient3 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclien',),
            ('root      ','root      ', '2146', '    1' , '  0.0', '  0.0', '   2652', '   360', ' ?        ', 'S    ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/rpcbind -w',),
            ('statd     ','statd     ', '2147', '    1' , '  0.0', '  0.0', '  28256', '  2200', ' ?        ', 'S    ', ' 0 ', ' May20 ', '   0:00 ', '/sbin/rpc.statd',),
            ('root      ','root      ', '2148', '    2' , '  0.0', '  0.0', '   1880', '   620', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '[rpciod]',),
            ('root      ','root      ', '2150', '    2' , '  0.0', '  0.0', '   2180', '   592', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '[nfsiod]',),
            ('root      ','root      ', '2151', '    1' , '  0.0', '  0.0', '   2156', '  1100', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '/usr/sbin/rpc.idmapd',),
            ('root      ','root      ', '2153', '    1' , '  0.0', '  0.0', '   3840', '  1284', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '/usr/sbin/rsyslogd -c5',),
            ('root      ','root      ', '2155', '    1' , '  0.0', '  0.0', '   1880', '   976', ' ?        ', 'S    ', ' 0 ', ' May20 ', '   0:00 ', '/usr/sbin/acpid',),
            ('root      ','root      ', '4969', '    1' , '  0.0', '  0.1', '   5416', '  1024', ' ?        ', 'Ss   ', ' 0 ', ' May20 ', '   0:00 ', '/usr/sbin/sshd: %s@pts/0' % user,),
            ('%s'.ljust(8) % user, '%s'.ljust(8) % user, '6567', ' 8132' , '  0.0', '  0.2', '   2924', '  1540', ' pts/0    ', 'Ss   ', ' 0 ', ' 04:30 ', '   0:00 ', '-bash',),
            ('%s'.ljust(8) % user, '%s'.ljust(8) % user, '7966', ' 9722' , '  0.0', '  0.1', '   2432', '   928', ' pts/0    ', 'R+   ', ' 0 ', ' 04:32 ', '   0:00 ', 'ps %s' % ' '.join(self.args),)
        )
        for i in range(len(output)):
            if i != 0:
                if 'a' not in args and 'e' not in args and output[i][_user].strip() != user:
                    continue
                elif 'a' not in args and 'x' not in args and 'e' not in args \
                        and output[i][_tty].strip() != 'pts/0':
                    continue
            l = [_pid, _tty, _time, _command]
            if 'e' in args:
                l = [_pid, _tty, _time, _command]
            if 'f' in args:
                l = [_uid, _pid, _ppid, _c, _start, _tty, _time, _command]
            if 'a' in args or 'x' in args:
                l = [_pid, _tty, _stat, _time, _command]
            if 'u' in args:
                l = [_user, _pid, _cpu, _mem, _vsz, _rss, _tty, _stat,
                    _start, _time, _command]
            s = ''.join([output[i][x] for x in l])
            if 'w' not in args:
                s = s[:80]
            self.writeln(s)
commands['/bin/ps'] = command_ps

class command_id(HoneyPotCommand):
    def call(self):
        u = self.honeypot.user
        self.writeln('uid=%d(%s) gid=%d(%s) groups=%d(%s)' % \
            (u.uid, u.username, u.gid, u.username, u.gid, u.username))
commands['/usr/bin/id'] = command_id

class command_passwd(HoneyPotCommand):
    def start(self):
        self.write('Enter new UNIX password: ')
        self.honeypot.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None

    def ask_again(self, line):
        self.passwd = line
        self.write('Retype new UNIX password: ')

    def finish(self, line):
        self.honeypot.password_input = False

        if line != self.passwd or self.passwd == '*':
            self.writeln('Sorry, passwords do not match')
            self.exit()
            return

        userdb = UserDB()
        userdb.adduser(self.honeypot.user.username,
            self.honeypot.user.uid, self.passwd)

        self.writeln('passwd: password updated successfully')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT (passwd):', line
        self.password = line.strip()
        self.callbacks.pop(0)(line)
commands['/usr/bin/passwd'] = command_passwd

class command_shutdown(HoneyPotCommand):
    def start(self):
        if len(self.args) and self.args[0].strip().count('--help'):
            output = (
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. " ,
                "-r:      reboot after shutdown. " ,
                "-h:      halt after shutdown. " ,
                "-P:      halt action is to turn off power. " ,
                "-H:      halt action is to just halt. " ,
                "-f:      do a 'fast' reboot (skip fsck). " ,
                "-F:      Force fsck on reboot. " ,
                "-n:      do not go through \"init\" but go down real fast. " ,
                "-c:      cancel a running shutdown. " ,
                "-t secs: delay between warning and kill signal. " ,
                "** the \"time\" argument is mandatory! (try \"now\") **",
                )
            for l in output:
                self.writeln(l)
            self.exit()
        elif len(self.args) > 1 and self.args[0].strip().count('-h') \
                and self.args[1].strip().count('now'):
            self.nextLine()
            self.writeln(
                'Broadcast message from root@%s (pts/0) (%s):' % \
                (self.honeypot.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for maintenance NOW!')
            reactor.callLater(3, self.finish)
        elif len(self.args) > 1 and self.args[0].strip().count('-r') \
                and self.args[1].strip().count('now'):
            self.nextLine()
            self.writeln(
                'Broadcast message from root@%s (pts/0) (%s):' % \
                (self.honeypot.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for reboot NOW!')
            reactor.callLater(3, self.finish)
        else:
            self.writeln("Try `shutdown --help' for more information.")
            self.exit()
            return

    def finish(self):
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
        self.exit()
commands['/sbin/shutdown'] = command_shutdown

class command_reboot(HoneyPotCommand):
    def start(self):
        self.nextLine()
        self.writeln(
            'Broadcast message from root@%s (pts/0) (%s):' % \
            (self.honeypot.hostname, time.ctime()))
        self.nextLine()
        self.writeln('The system is going down for reboot NOW!')
        reactor.callLater(3, self.finish)

    def finish(self):
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
        self.honeypot.uptime(time.time())
        self.exit()
commands['/sbin/reboot'] = command_reboot

class command_history(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0] == '-c':
            self.honeypot.historyLines = []
            self.honeypot.historyPosition = 0
            return
        count = 1
        for l in self.honeypot.historyLines:
            self.writeln(' %s  %s' % (str(count).rjust(4), l))
            count += 1
commands['history'] = command_history

class command_date(HoneyPotCommand):
    def call(self):
        time = datetime.datetime.utcnow();
        self.writeln(time.strftime("%a %b %d %H:%M:%S UTC %Y"))
commands['/bin/date'] = command_date

class command_yes(HoneyPotCommand):
    def start(self):
        self.y()

    def y(self):
        self.writeln('y')
        self.scheduled = reactor.callLater(0.01, self.y)

    def ctrl_c(self):
        self.scheduled.cancel()
        self.exit()
commands['/usr/bin/yes'] = command_yes

class command_sh(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() == '-c':
            self.honeypot.cmdstack[0].cmdpending.append(
                ' '.join(self.args[1:]))
commands['/bin/bash'] = command_sh
commands['/bin/sh'] = command_sh


class command_chmod(HoneyPotCommand):
    def call(self):
        if len(self.args) < 2:
            self.writeln('chmod: missing operand')
            self.writeln('Try chmod --help for more information.')
            return
        for arg in self.args[1:]:
            path = self.fs.resolve_path(arg, self.honeypot.cwd)
            if not self.fs.exists(path):
                self.writeln(
                    'chmod: cannot access %s: No such file or directory' % \
                    (arg,))
commands['/bin/chmod'] = command_chmod

class command_perl(HoneyPotCommand):
    def start(self):
        if not len(self.args):
            pass
        elif self.args[0] == '-v':
            output = (
                '',
                'This is perl 5, version 14, subversion 2 (v5.14.2) built for x86_64-linux-thread-multi',
                '',
                'Copyright 1987-2014, Larry Wall',
                '',
                'Perl may be copied only under the terms of either the Artistic License or the',
                'GNU General Public License, which may be found in the Perl 5 source kit.',
                '',
                'Complete documentation for Perl, including FAQ lists, should be found on',
                'this system using "man perl" or "perldoc perl".  If you have access to the',
                'Internet, point your browser at http://www.perl.org/, the Perl Home Page.',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        elif self.args[0] == '-h':
            output = (
                '',
                'Usage: perl [switches] [--] [programfile] [arguments]',
                '  -0[octal]         specify record separator (\0, if no argument)',
                '  -a                autosplit mode with -n or -p (splits $_ into @F)',
                '  -C[number/list]   enables the listed Unicode features',
                '  -c                check syntax only (runs BEGIN and CHECK blocks)',
                '  -d[:debugger]     run program under debugger',
                '  -D[number/list]   set debugging flags (argument is a bit mask or alphabets)',
                "  -e program        one line of program (several -e's allowed, omit programfile)",
                '  -E program        like -e, but enables all optional features',
                "  -f                don't do $sitelib/sitecustomize.pl at startup",
                "  -F/pattern/       split() pattern for -a switch (//'s are optional)",
                '  -i[extension]     edit <> files in place (makes backup if extension supplied)',
                "  -Idirectory       specify @INC/#include directory (several -I's allowed)",
                '  -l[octal]         enable line ending processing, specifies line terminator',
                '  -[mM][-]module    execute "use/no module..." before executing program',
                '  -n                assume "while (<>) { ... }" loop around program',
                '  -p                assume loop like -n but print line also, like sed',
                '  -s                enable rudimentary parsing for switches after programfile',
                '  -S                look for programfile using PATH environment variable',
                '  -t                enable tainting warnings',
                '  -T                enable tainting checks',
                '  -u                dump core after parsing program',
                '  -U                allow unsafe operations',
                '  -v                print version, subversion (includes VERY IMPORTANT perl info)',
                '  -V[:variable]     print configuration summary (or a single Config.pm variable)',
                '  -w                enable many useful warnings (RECOMMENDED)',
                '  -W                enable all warnings',
                '  -x[directory]     strip off text before #!perl line and perhaps cd to directory',
                '  -X                disable all warnings',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        else:
            self.exit()

    def lineReceived(self, line):
        print 'INPUT (perl):', line
commands['/usr/bin/perl'] = command_perl

class command_php(HoneyPotCommand):
    def start(self):
        if not len(self.args):
            pass
        elif self.args[0] == '-v':
            output = (
                'PHP 5.3.5 (cli)',
                'Copyright (c) 1997-2010 The PHP Group'
            )
            for l in output:
                self.writeln(l)
            self.exit()
        elif self.args[0] == '-h':
            output = (
                'Usage: php [options] [-f] <file> [--] [args...]',
                '       php [options] -r <code> [--] [args...]',
                '       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]',
                '       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]',
                '       php [options] -- [args...]',
                '       php [options] -a',
                '',
                '  -a               Run interactively',
                '  -c <path>|<file> Look for php.ini file in this directory',
                '  -n               No php.ini file will be used',
                "  -d foo[=bar]     Define INI entry foo with value 'bar'",
                '  -e               Generate extended information for debugger/profiler',
                '  -f <file>        Parse and execute <file>.',
                '  -h               This help',
                '  -i               PHP information',
                '  -l               Syntax check only (lint)',
                '  -m               Show compiled in modules',
                '  -r <code>        Run PHP <code> without using script tags <?..?>',
                '  -B <begin_code>  Run PHP <begin_code> before processing input lines',
                '  -R <code>        Run PHP <code> for every input line',
                '  -F <file>        Parse and execute <file> for every input line',
                '  -E <end_code>    Run PHP <end_code> after processing all input lines',
                '  -H               Hide any passed arguments from external tools.',
                '  -s               Output HTML syntax highlighted source.',
                '  -v               Version number',
                '  -w               Output source with stripped comments and whitespace.',
                '  -z <file>        Load Zend extension <file>.',
                '',
                '  args...          Arguments passed to script. Use -- args when first argument',
                '                   starts with - or script is read from stdin',
                '',
                '  --ini            Show configuration file names',
                '',
                '  --rf <name>      Show information about function <name>.',
                '  --rc <name>      Show information about class <name>.',
                '  --re <name>      Show information about extension <name>.',
                '  --ri <name>      Show configuration for extension <name>.',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        else:
            self.exit()

    def lineReceived(self, line):
        print 'INPUT (php):', line
commands['/usr/bin/php'] = command_php

class command_nop(HoneyPotCommand):
    def call(self):
        pass
commands['umask'] = command_nop
commands['set'] = command_nop
commands['unset'] = command_nop
commands['export'] = command_nop
commands['alias'] = command_nop
commands['/bin/kill'] = command_nop
commands['/bin/su'] = command_nop
commands['/bin/chown'] = command_nop
commands['/bin/chgrp'] = command_nop
commands['/usr/bin/chattr'] = command_nop

# vim: set sw=4 et:
