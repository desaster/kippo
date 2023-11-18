# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import stat
import time

from kippo.core.fs import *
from kippo.core.honeypot import HoneyPotCommand

commands = {}


class command_ls(HoneyPotCommand):

    def uid2name(self, uid):
        return 'root' if uid == 0 else uid

    def gid2name(self, gid):
        return 'root' if gid == 0 else gid

    def call(self):
        path = self.honeypot.cwd
        paths = []
        if len(self.args):
            paths.extend(
                self.honeypot.fs.resolve_path(arg, self.honeypot.cwd)
                for arg in self.args
                if not arg.startswith('-')
            )
        self.show_hidden = False
        func = self.do_ls_normal
        for x in self.args:
            if x.startswith('-') and x.count('l'):
                func = self.do_ls_l
            if x.startswith('-') and x.count('a'):
                self.show_hidden = True

        if not paths:
            func(path)
        else:
            for path in paths:
                func(path)

    def do_ls_normal(self, path):
        try:
            files = self.honeypot.fs.get_path(path)
        except Exception:
            self.honeypot.writeln(f'ls: cannot access {path}: No such file or directory')
            return
        l = [x[A_NAME] for x in files \
                         if self.show_hidden or not x[A_NAME].startswith('.')]
        if self.show_hidden:
            l.insert(0, '..')
            l.insert(0, '.')
        if not l:
            return
        count = 0
        maxlen = max(len(x) for x in l)

        try:
            wincols = self.honeypot.user.windowSize[1]
        except AttributeError:
            wincols = 80

        perline = int(wincols / (maxlen + 1))
        for f in l:
            if count == perline:
                count = 0
                self.nextLine()
            self.write(f.ljust(maxlen + 1))
            count += 1
        self.nextLine()

    def do_ls_l(self, path):
        try:
            files = self.honeypot.fs.get_path(path)[:]
        except Exception:
            self.honeypot.writeln(f'ls: cannot access {path}: No such file or directory')
            return

        largest = max(x[A_SIZE] for x in files) if len(files) else 0
        # FIXME: should grab these off the parents instead
        files.insert(0,
                     ['..', T_DIR, 0, 0, 4096, 16877, time.time(), [], None])
        files.insert(0,
                     ['.', T_DIR, 0, 0, 4096, 16877, time.time(), [], None])
        for file in files:
            perms = ['-'] * 10

            if file[A_MODE] & stat.S_IRUSR: perms[1] = 'r'
            if file[A_MODE] & stat.S_IWUSR: perms[2] = 'w'
            if file[A_MODE] & stat.S_IXUSR: perms[3] = 'x'

            if file[A_MODE] & stat.S_IRGRP: perms[4] = 'r'
            if file[A_MODE] & stat.S_IWGRP: perms[5] = 'w'
            if file[A_MODE] & stat.S_IXGRP: perms[6] = 'x'

            if file[A_MODE] & stat.S_IROTH: perms[7] = 'r'
            if file[A_MODE] & stat.S_IWOTH: perms[8] = 'w'
            if file[A_MODE] & stat.S_IXOTH: perms[9] = 'x'

            linktarget = ''

            if file[A_TYPE] == T_DIR:
                perms[0] = 'd'
            elif file[A_TYPE] == T_LINK:
                perms[0] = 'l'
                linktarget = f' -> {file[A_TARGET]}'

            perms = ''.join(perms)
            ctime = time.localtime(file[A_CTIME])

            l = f"{perms} 1 {self.uid2name(file[A_UID])} {self.gid2name(file[A_GID])} {str(file[A_SIZE]).rjust(len(str(largest)))} {time.strftime('%Y-%m-%d %H:%M', ctime)} {file[A_NAME]}{linktarget}"

            self.honeypot.writeln(l)


commands['/bin/ls'] = command_ls

# vim: set sw=4 et:
