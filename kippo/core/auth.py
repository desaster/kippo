# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import string

import twisted
from twisted.cred import checkers, credentials, error
from twisted.internet import defer
from zope.interface import implements

from kippo.core.config import config

# by Walter de Jong <walter@sara.nl>
class UserDB(object):

    def __init__(self):
        self.userdb = []
        self.load()

    def load(self):
        '''load the user db'''

        userdb_file = f"{config().get('honeypot', 'data_path')}/userdb.txt"

        with open(userdb_file, 'r') as f:
            while True:
                line = f.readline()
                if not line:
                    break

                line = string.strip(line)
                if not line:
                    continue

                (login, uid_str, passwd) = line.split(':', 2)

                uid = 0
                try:
                    uid = int(uid_str)
                except ValueError:
                    uid = 1001

                self.userdb.append((login, uid, passwd))

    def save(self):
        '''save the user db'''

        userdb_file = f"{config().get('honeypot', 'data_path')}/userdb.txt"

        with open(userdb_file, 'w') as f:
            for (login, uid, passwd) in self.userdb:
                f.write('%s:%d:%s\n' % (login, uid, passwd))

    def checklogin(self, thelogin, thepasswd):
        '''check entered username/password against database'''
        '''note that it allows multiple passwords for a single username'''

        return any(
            login == thelogin and passwd in (thepasswd, '*')
            for login, uid, passwd in self.userdb
        )

    def user_exists(self, thelogin):
        return any(login == thelogin for login, uid, passwd in self.userdb)

    def user_password_exists(self, thelogin, thepasswd):
        return any(
            login == thelogin and passwd == thepasswd
            for login, uid, passwd in self.userdb
        )

    def getUID(self, loginname):
        return next(
            (uid for login, uid, passwd in self.userdb if loginname == login), 1001
        )

    def allocUID(self):
        '''allocate the next UID'''

        min_uid = 0
        for (login, uid, passwd) in self.userdb:
            if uid > min_uid:
                min_uid = uid
        return min_uid + 1

    def adduser(self, login, uid, passwd):
        if self.user_password_exists(login, passwd):
            return
        self.userdb.append((login, uid, passwd))
        self.save()

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

# vim: set sw=4 et:
