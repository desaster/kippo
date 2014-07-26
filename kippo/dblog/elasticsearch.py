from kippo.core import dblog
import collections
import pyes
import GeoIP
import time
import json
import uuid
import os

# This is the ES mapping, we mostly need it to mark specific fields as "not_analyzed"
kippo_mapping = {
    "client": {
        "type": "string",
        "index": "not_analyzed"
    },
    "country": {
        "type": "string"
    },
    "ip": {
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
        "type": "long"
    },
    "timestamp": {
        "type": "date",
        "format": "dateOptionalTime"
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

    def handleLoginAttempt(self, session, args, success):
        login_dict = collections.OrderedDict()
        login_dict['session'] = session
        login_dict['success'] = success
        login_dict['username'] = args['username']
        login_dict['password'] = args['password']
        login_dict['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
        login_dict['country'] = self.geoip.country_code_by_addr(self.remote_ip)
        login_dict['ip'] = self.remote_ip
        login_dict['client'] = self.client_version
        login_dict['sensor'] = self.sensor_ip
        auth_json = json.dumps(login_dict)
        self.es_conn.index(auth_json, self.es_index, self.es_type)

    def handleLoginFailed(self, session, args):
        self.handleLoginAttempt(session, args, 0)

    def handleLoginSucceeded(self, session, args):
        self.handleLoginAttempt(session, args, 1)