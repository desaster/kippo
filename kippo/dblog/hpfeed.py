##################################################
#
#
import os
import sys
import datetime
import time
import csv
import sys
import pygeoip
import json
import select
import traceback
import logging
from kippo.core import dblog
from twisted.python import log
import uuid
import hpfeeds
import logging
logging.basicConfig()
logger = logging.getLogger('hpfeed')
hdlr = logging.FileHandler('/var/tmp/hpfeed.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.sessions= {}
        self.HOST = cfg.get('database_hpfeed', "host")
        self.PORT = int(cfg.get('database_hpfeed', "port"))
        self.CHANNELS= []
        self.CHANNELS.append(cfg.get("database_hpfeed", "channel"))
        self.gd  = pygeoip.GeoIP(cfg.get('database_hpfeed', 'geolitecity'))
        self.IDENT = cfg.get("database_hpfeed", 'ident')
        self.SECRET = cfg.get("database_hpfeed", 'secret')
        self.hpc = hpfeeds.new(self.HOST, self.PORT, self.IDENT, self.SECRET)

        log.msg('connected to %s'% self.hpc.brokername)
        logger.info("Connected to %s" % self.hpc.brokername)
    def write(self, session, msg):
        logger.info("msg: %s" % msg)
        peerIP = self.sessions[session]["peerIP"]
        d = self.gd.record_by_addr(peerIP)
        if d== None:
            d = {}
            d['latitude']= 25.03
            d['longitude'] = 121.53
            d['country_code'] = 'TW'
        dat = {}
        dat["latitude"] = d["latitude"]
        dat["longitude"] = d["longitude"]
        dat["type"] = "%s: %s" % (peerIP, msg)
        dat["countrycode"] = d["country_code"]
        dat["city"] = d["city"]
        fmsg = json.dumps(dat)
        self.hpc.publish(self.CHANNELS, fmsg)


    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex
        self.sessions[sid] = {}
        self.sessions[sid]["peerIP"] = peerIP
        self.sessions[sid]["peerPort"]= peerPort
        self.sessions[sid]["hostIP"] = hostIP
        self.sessions[sid]["hostPort"] = ["hostPort"]
        self.sessions[sid]["sensorname"] = self.getSensor() or hostIP
        self.write(sid, 'New connection: %s:%s' % (peerIP, peerPort))
        return sid

    def handleConnectionLost(self, session, args):
        self.write(session, 'Connection lost')
        del self.sessions[session]

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


