# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import random
import re

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks

from kippo.core.honeypot import HoneyPotCommand

commands = {}


class command_faked_package_class_factory(object):
    @staticmethod
    def getCommand(name):



        class command_faked_installation(HoneyPotCommand):
            def call(self):
                self.writeln(f"{name}: Segmentation fault")


        return command_faked_installation


'''apt-get fake
suppports only the 'install PACKAGE' command & 'moo'.
Any installed packages, places a 'Segfault' at /usr/bin/PACKAGE.'''


class command_aptget(HoneyPotCommand):
    def start(self):
        if len(self.args) > 0 and self.args[0] == 'install':
            self.do_install()
        elif len(self.args) > 0 and self.args[0] == 'moo':
            self.do_moo()
        else:
            self.do_locked()

    def sleep(self, time, time2=None):
        d = defer.Deferred()
        if time2:
            time = random.randint(time * 100, time2 * 100) / 100.0
        reactor.callLater(time, d.callback, None)
        return d

    @inlineCallbacks
    def do_install(self, *args):
        if len(self.args) <= 1:
            self.writeln(
                f'0 upgraded, 0 newly installed, 0 to remove and {random.randint(200, 300)} not upgraded.'
            )
            self.exit()
            return

        packages = {
            y: {
                'version': '%d.%d-%d'
                % (
                    random.choice((0, 1)),
                    random.randint(1, 40),
                    random.randint(1, 10),
                ),
                'size': random.randint(100, 900),
            }
            for y in [re.sub('[^A-Za-z0-9]', '', x) for x in self.args[1:]]
        }
        totalsize = sum(packages[x]['size'] for x in packages)

        self.writeln('Reading package lists... Done')
        self.writeln('Building dependency tree')
        self.writeln('Reading state information... Done')
        self.writeln('The following NEW packages will be installed:')
        self.writeln(f"  {' '.join(packages)} ")
        self.writeln('0 upgraded, %d newly installed, 0 to remove and 259 not upgraded.' % \
                         len(packages))
        self.writeln(f'Need to get {totalsize}.2kB of archives.')
        self.writeln(
            f'After this operation, {totalsize * 2.2}kB of additional disk space will be used.'
        )
        for i, (p, value) in enumerate(packages.items(), start=1):
            self.writeln(
                'Get:%d http://ftp.debian.org stable/main %s %s [%s.2kB]'
                % (i, p, value['version'], packages[p]['size'])
            )
            yield self.sleep(1, 2)
        self.writeln(f'Fetched {totalsize}.2kB in 1s (4493B/s)')
        self.writeln('Reading package fields... Done')
        yield self.sleep(1, 2)
        self.writeln('Reading package status... Done')
        self.writeln('(Reading database ... 177887 files and directories currently installed.)')
        yield self.sleep(1, 2)
        for p, value_ in packages.items():
            self.writeln(
                f"Unpacking {p} (from .../archives/{p}_{value_['version']}_i386.deb) ..."
            )
            yield self.sleep(1, 2)
        self.writeln('Processing triggers for man-db ...')
        yield self.sleep(2)
        for p, value__ in packages.items():
            self.writeln(f"Setting up {p} ({value__['version']}) ...")
            self.fs.mkfile(f'/usr/bin/{p}', 0, 0, random.randint(10000, 90000), 33188)
            self.honeypot.commands[
                f'/usr/bin/{p}'
            ] = command_faked_package_class_factory.getCommand(p)
            yield self.sleep(2)
        self.exit()

    def do_moo(self):
        self.writeln('         (__)')
        self.writeln('         (oo)')
        self.writeln('   /------\/')
        self.writeln('  / |    ||')
        self.writeln(' *  /\---/\ ')
        self.writeln('    ~~   ~~')
        self.writeln('...."Have you mooed today?"...')
        self.exit()

    def do_locked(self):
        self.writeln('E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)')
        self.writeln('E: Unable to lock the list directory')
        self.exit()


commands['/usr/bin/apt-get'] = command_aptget

# vim: set sw=4 et tw=0:
