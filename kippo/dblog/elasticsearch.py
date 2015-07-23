import collections
import GeoIP
import time
import json
import uuid
import os

import pyes
import pyes.exceptions
from twisted.python import log

from kippo.core import dblog


# This is the ES mapping, we mostly need it to mark specific fields as "not_analyzed"
kippo_mapping = {
    "client": {
        "type": "string",
        "index": "not_analyzed"
    },
    "country": {
        "type": "string"
    },
    "input": {
        "type": "string",
        "index": "not_analyzed"
    },
    "ip": {
        "type": "string",
        "index": "not_analyzed",
        "fields": {
            "ipv4": {
                "type": "ip",
            }
        }
    },
    "log_type": {
        "type": "string"
    },
    "outfile": {
        "type": "string",
        "index": "not_analyzed"
    },
    "password": {
        "type": "string",
        "index": "not_analyzed"
    },
    "sensor": {
        "type": "string",
        "index": "not_analyzed"
    },
    "session": {
        "type": "string",
        "index": "not_analyzed"
    },
    "success": {
        "type": "boolean"
    },
    "timestamp": {
        "type": "date",
        "format": "dateOptionalTime"
    },
    "url": {
        "type": "string",
        "index": "not_analyzed"
    },
    "username": {
        "type": "string",
        "index": "not_analyzed"
    }
}


class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.es_host = cfg.get('database_elasticsearch', 'host')
        self.es_port = cfg.get('database_elasticsearch', 'port')
        self.es_index = cfg.get('database_elasticsearch', 'index')
        self.es_type = cfg.get('database_elasticsearch', 'type')
        self.es_conn = pyes.ES('{0}:{1}'.format(self.es_host, self.es_port))
        self.run(cfg)

    def run(self, cfg):
        self.geoip = GeoIP.open(os.path.join(os.path.dirname(__file__), "geoip/GeoIP.dat"), GeoIP.GEOIP_STANDARD)
        self.es_conn.indices.create_index_if_missing(self.es_index)
        self.es_conn.indices.put_mapping(self.es_type, {'properties': kippo_mapping}, [self.es_index])

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        self.remote_ip = peerIP
        self.sensor_ip = self.getSensor() or hostIP
        sid = uuid.uuid1().hex
        return sid

    def handleClientVersion(self, session, args):
        self.client_version = args['version']

    def send_to_elasticsearch(self, json_doc):
        self.es_conn.index(json_doc, self.es_index, self.es_type)

    def handleLoginAttempt(self, session, args, success):
        login_dict = collections.OrderedDict()
        login_dict['log_type'] = "login_attempt"
        login_dict['session'] = session
        login_dict['success'] = success
        login_dict['username'] = args['username']
        login_dict['password'] = args['password']
        login_dict['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        login_dict['country'] = self.geoip.country_code_by_addr(self.remote_ip)
        login_dict['ip'] = self.remote_ip
        login_dict['client'] = self.client_version
        login_dict['sensor'] = self.sensor_ip
        login_json = json.dumps(login_dict)
        self.send_to_elasticsearch(login_json)

    def handleLoginFailed(self, session, args):
        self.handleLoginAttempt(session, args, 0)

    def handleLoginSucceeded(self, session, args):
        self.handleLoginAttempt(session, args, 1)

    def handleCommandAttempt(self, session, args, success):
        command_dict = collections.OrderedDict()
        command_dict['log_type'] = "command"
        command_dict['session'] = session
        command_dict['success'] = success
        command_dict['input'] = args['input']
        command_dict['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        command_dict['country'] = self.geoip.country_code_by_addr(self.remote_ip)
        command_dict['ip'] = self.remote_ip
        command_dict['client'] = self.client_version
        command_dict['sensor'] = self.sensor_ip
        command_json = json.dumps(command_dict)
        self.send_to_elasticsearch(command_json)

    def handleCommand(self, session, args):
        self.handleCommandAttempt(session, args, 1)

    def handleUnknownCommand(self, session, args):
        self.handleCommandAttempt(session, args, 0)

    def handleFileDownload(self, session, args):
        download_dict = collections.OrderedDict()
        download_dict['log_type'] = "download"
        download_dict['session'] = session
        download_dict['url'] = args['url']
        download_dict['outfile'] = args['outfile']
        download_dict['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        download_dict['country'] = self.geoip.country_code_by_addr(self.remote_ip)
        download_dict['ip'] = self.remote_ip
        download_dict['client'] = self.client_version
        download_dict['sensor'] = self.sensor_ip
        download_json = json.dumps(download_dict)
        self.send_to_elasticsearch(download_json)