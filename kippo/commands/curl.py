# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import stat
import time
import urlparse
import random
import re
import exceptions
import os
import getopt
import hashlib

from twisted.web import client
from twisted.internet import reactor
from twisted.python import log

from kippo.core.honeypot import HoneyPotCommand
from kippo.core.fs import *

commands = {}

def tdiff(seconds):
    t = seconds
    days = int(t / (24 * 60 * 60))
    t -= (days * 24 * 60 * 60)
    hours = int(t / (60 * 60))
    t -= (hours * 60 * 60)
    minutes = int(t / 60)
    t -= (minutes * 60)

    s = '%ds' % int(t)
    if minutes >= 1: s = '%dm %s' % (minutes, s)
    if hours >= 1: s = '%dh %s' % (hours, s)
    if days >= 1: s = '%dd %s' % (days, s)
    return s

def sizeof_fmt(num):
    for x in ['bytes','K','M','G','T']:
        if num < 1024.0:
            return "%d%s" % (num, x)
        num /= 1024.0

# Luciano Ramalho @ http://code.activestate.com/recipes/498181/
def splitthousands( s, sep=','):
    if len(s) <= 3: return s
    return splitthousands(s[:-3], sep) + sep + s[-3:]

class command_curl(HoneyPotCommand):
    def start(self):
        try:
            optlist, args = getopt.getopt(self.args, 'o:O')
        except getopt.GetoptError as err:
            self.writeln('Unrecognized option')
            self.exit()
            return

        if len(args):
            url = args[0].strip()
        else:
            self.writeln("curl: try 'curl --help' or 'curl --manual' for more information'")
            self.exit()
            return

        if '://' not in url:
            url = 'http://%s' % url
        urldata = urlparse.urlparse(url)

        outfile = None
        for opt in optlist:
            if opt[0] == '-o':
                outfile = opt[1]
            if opt[0] == '-O':
                outfile = urldata.path.split('/')[-1]
                if not len(outfile.strip()) or not urldata.path.count('/'):
                    self.writeln('curl: Remote file name has no length!')
                    self.exit()
                    return

        if outfile:
            outfile = self.fs.resolve_path(outfile, self.honeypot.cwd)
            path = os.path.dirname(outfile)
            if not path or \
                    not self.fs.exists(path) or \
                    not self.fs.is_dir(path):
                self.writeln('curl: %s: Cannot open: No such file or directory' % \
                    outfile)
                self.exit()
                return

        self.url = url
        self.limit_size = 0
        cfg = self.honeypot.env.cfg
        if cfg.has_option('honeypot', 'download_limit_size'):
            self.limit_size = int(cfg.get('honeypot', 'download_limit_size'))

        self.download_path = cfg.get('honeypot', 'download_path')

        self.safeoutfile = '%s/%s_%s' % \
            (self.download_path,
            time.strftime('%Y%m%d%H%M%S'),
            re.sub('[^A-Za-z0-9]', '_', url))
        self.deferred = self.download(url, outfile, self.safeoutfile)
        if self.deferred:
            self.deferred.addCallback(self.success, outfile)
            self.deferred.addErrback(self.error, url)

    def download(self, url, fakeoutfile, outputfile, *args, **kwargs):
        try:
            parsed = urlparse.urlparse(url)
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == 'https' else 80)
            path = parsed.path or '/'
            if scheme == 'https':
                self.writeln('Sorry, SSL not supported in this release')
                self.exit()
                return None
            elif scheme != 'http':
                raise exceptions.NotImplementedError
        except:
            self.writeln('%s: Unsupported scheme.' % (url,))
            self.exit()
            return None

        #self.writeln('--%s--  %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), url))
        #self.writeln('Connecting to %s:%d... connected.' % (host, port))
        #self.write('HTTP request sent, awaiting response... ')

        factory = HTTPProgressDownloader(
            self, fakeoutfile, url, outputfile, *args, **kwargs)
        out_addr = None
        if self.honeypot.env.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.honeypot.env.cfg.get('honeypot', 'out_addr'), 0)
        self.connection = reactor.connectTCP(
            host, port, factory, bindAddress=out_addr)
        return factory.deferred

    def ctrl_c(self):
        self.writeln('^C')
        self.connection.transport.loseConnection()

    def success(self, data, outfile):
        if not os.path.isfile(self.safeoutfile):
            log.msg("there's no file " + self.safeoutfile)
            self.exit()

        shasum = hashlib.sha256(open(self.safeoutfile, 'rb').read()).hexdigest()
        hash_path = '%s/%s' % (self.download_path, shasum)

        # if we have content already, delete temp file
        if not os.path.exists(hash_path):
            os.rename(self.safeoutfile, hash_path)
        else:
            os.remove(self.safeoutfile)
            log.msg("Not storing duplicate content " + shasum)

        self.honeypot.logDispatch(format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
            eventid='KIPP0007', url=self.url, outfile=hash_path, shasum=shasum)

        log.msg(format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
            eventid='KIPP0007', url=self.url, outfile=hash_path, shasum=shasum)

        # link friendly name to hash
        os.symlink(shasum, self.safeoutfile)

        # FIXME: is this necessary?
        self.safeoutfile = hash_path

        # update the honeyfs to point to downloaded file
        f = self.fs.getfile(outfile)
        f[A_REALFILE] = hash_path
        self.exit()

    def error(self, error, url):
        if hasattr(error, 'getErrorMessage'): # exceptions
            error = error.getErrorMessage()
        self.writeln(error)
        # Real curl also adds this:
        #self.writeln('%s ERROR 404: Not Found.' % \
        #    time.strftime('%Y-%m-%d %T'))
        self.exit()
commands['/usr/bin/curl'] = command_curl

# from http://code.activestate.com/recipes/525493/
class HTTPProgressDownloader(client.HTTPDownloader):
    def __init__(self, curl, fakeoutfile, url, outfile, headers=None):
        client.HTTPDownloader.__init__(self, url, outfile, headers=headers,
            agent='curl/7.38.0')
        self.status = None
        self.curl = curl
        self.fakeoutfile = fakeoutfile
        self.lastupdate = 0
        self.started = time.time()
        self.proglen = 0
        self.nomore = False

    def noPage(self, reason): # called for non-200 responses
        if self.status == '304':
            client.HTTPDownloader.page(self, '')
        else:
            client.HTTPDownloader.noPage(self, reason)

    def gotHeaders(self, headers):
        if self.status == '200':
            #self.curl.writeln('200 OK')
            if headers.has_key('content-length'):
                self.totallength = int(headers['content-length'][0])
            else:
                self.totallength = 0
            if headers.has_key('content-type'):
                self.contenttype = headers['content-type'][0]
            else:
                self.contenttype = 'text/whatever'
            self.currentlength = 0.0

            #if self.totallength > 0:
            #    self.curl.writeln('Length: %d (%s) [%s]' % \
            #        (self.totallength,
            #        sizeof_fmt(self.totallength),
            #        self.contenttype))
            #else:
            #    self.curl.writeln('Length: unspecified [%s]' % \
            #        (self.contenttype))

            if self.curl.limit_size > 0 and \
                    self.totallength > self.curl.limit_size:
                log.msg('Not saving URL (%s) due to file size limit' % \
                    (self.curl.url,))
                self.fileName = os.path.devnull
                self.nomore = True
            #self.curl.writeln('Saving to: `%s' % self.fakeoutfile)
            #self.curl.honeypot.terminal.nextLine()

            if self.fakeoutfile:
                self.curl.writeln('  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current')
                self.curl.writeln('                                 Dload  Upload   Total   Spent    Left  Speed')

        return client.HTTPDownloader.gotHeaders(self, headers)

    def pagePart(self, data):
        if self.status == '200':
            self.currentlength += len(data)

            # if downloading files of unspecified size, this could happen:
            if not self.nomore and self.curl.limit_size > 0 and \
                    self.currentlength > self.curl.limit_size:
                log.msg('File limit reached, not saving any more data!')
                self.nomore = True
                self.file.close()
                self.fileName = os.path.devnull
                self.file = self.openFile(data)

            if (time.time() - self.lastupdate) < 0.5:
                return client.HTTPDownloader.pagePart(self, data)
            if self.totallength:
                percent = (self.currentlength/self.totallength)*100
                spercent = "%i%%" % percent
            else:
                spercent = '%dK' % (self.currentlength/1000)
                percent = 0
            self.speed = self.currentlength / (time.time() - self.started)
            #eta = (self.totallength - self.currentlength) / self.speed
            #s = '\r%s [%s] %s %dK/s  eta %s' % \
            #    (spercent.rjust(3),
            #    ('%s>' % (int(39.0 / 100.0 * percent) * '=')).ljust(39),
            #    splitthousands(str(int(self.currentlength))).ljust(12),
            #    self.speed / 1000,
            #    tdiff(eta))
            #self.curl.write(s.ljust(self.proglen))
            #self.proglen = len(s)
            self.lastupdate = time.time()
        return client.HTTPDownloader.pagePart(self, data)

    def pageEnd(self):
        if self.totallength != 0 and self.currentlength != self.totallength:
            return client.HTTPDownloader.pageEnd(self)
        #self.curl.write('\r100%%[%s] %s %dK/s' % \
        #    ('%s>' % (38 * '='),
        #    splitthousands(str(int(self.totallength))).ljust(12),
        #    self.speed / 1000))
        #self.curl.honeypot.terminal.nextLine()
        #self.curl.honeypot.terminal.nextLine()
        #self.curl.writeln(
        #    '%s (%d KB/s) - `%s\' saved [%d/%d]' % \
        #    (time.strftime('%Y-%m-%d %H:%M:%S'),
        #    self.speed / 1000,
        #    self.fakeoutfile, self.currentlength, self.totallength))

        if self.fakeoutfile:
            self.curl.write("\r100  %d  100  %d    0     0  %d      0 --:--:-- --:--:-- --:--:-- %d" % \
                (self.currentlength, self.currentlength  , 63673, 65181)
            )
            self.curl.honeypot.terminal.nextLine()

            self.curl.fs.mkfile(self.fakeoutfile, 0, 0, self.totallength, 33188)
            self.curl.fs.update_realfile(
                self.curl.fs.getfile(self.fakeoutfile),
                self.curl.safeoutfile)
        else:
            # stdout
            # write to stdout here
            self.curl.writeln("Your file here")

        self.curl.fileName = self.fileName
        return client.HTTPDownloader.pageEnd(self)

# vim: set sw=4 et:
