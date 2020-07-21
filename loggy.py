#!/usr/bin/env python3

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Loggy (Jr) - A log file grobbler for Python 3

import time
import logging
import watchdog.observers
import watchdog.events
import os
import json
import re
import collections
import base64
import hashlib
import elasticsearch
import elasticsearch.helpers
import threading
import socket
import yaml

# Disable most ES logging, or it'll litter syslog
tracer = logging.getLogger('elasticsearch')
tracer.setLevel(logging.CRITICAL)
tracer.addHandler(logging.FileHandler('loggy.log'))

DEBUG = False
inodes = {}
inodes_path = {}
filehandles = {}
mytags = ''

json_pending = {}
last_push = {}
config = None
dd_config = None
gotindex = {}
fp = {}
tag_overrides = {}

RSA_KEY = '/etc/ssh/ssh_host_rsa_key.pub'
FINGERPRINT = ''
FINGERPRINT_SHA = ''

es = None


regexes = {
    'apache_access': re.compile( 
            r"(?P<client_ip>[\d\.]+)\s" 
            r"(?P<identity>\S*)\s" 
            r"(?P<user>\S*)\s"
            r"\[(?P<time>.*?)\]\s"
            r'"(?P<request>.*?)"\s'
            r"(?P<status>\d+)\s"
            r"(?P<bytes>\S*)\s"
            r'"(?P<referer>.*?)"\s'
            r'"(?P<user_agent>.*?)"\s*'
        ),
    'apache_error': re.compile(
            r"\[(?P<date>.*?)\]\s+"
            r"\[(?P<module>.*?)\]\s+"
            r"\[(?P<pid>.*?)\]\s+"
            r"\[client\s+(?P<client_ip>[0-9.]+):\d+\]\s+"
            r"(?P<message>.+)"
        ),
    'syslog': re.compile( 
            r"(?P<date>\S+\s+\d+\s+\d+:\d+:\d+)\s+(<[0-9.]+>\s+)?" 
            r"(?P<host>\S+)\s+" 
            r"(?P<type>\S+):\s+"
            r"(?P<message>.+)"
        ),
    'fail2ban': re.compile( 
            r"(?P<date>\S+ \d+:\d+:[\d,]+)\s+" 
            r"(?P<type>fail2ban\.[^:]+):\s+"
            r"(?P<message>.+)"
        ),
    'rsync': re.compile( 
            r"(?P<date>\S+ \d+:\d+:[\d,]+)\s+" 
            r"\[(?P<pid>[\S.]+)\]\s+" 
            r"(?P<message>.+)"
        ),
    'pylogs': re.compile( 
            r"(?P<date>\S+ \S+)\s+\[pylog\]\s+" 
            r"\[(?P<type>[\S.]+)\]:\s+" 
            r"(?P<message>.+)"
        ),
    'qmail': re.compile( 
            r"(?P<mid>@[a-f0-9]+)\s+" 
            r"(?P<message>.+)"
        ),
    'lastlog': re.compile(
        r"(?P<user>[a-z0-9]+)\s+(?P<term>(pts/\d+|tty\d+|system))\s+"
        r"(?P<stats>.+)"
    )
}


# The names must agree with the regexes above
tuples = {
    'apache_access': collections.namedtuple('apache_access',
        ['client_ip', 'identity', 'user', 'time', 'request',
        'status', 'bytes', 'referer', 'user_agent',
        'filepath', 'logtype', 'timestamp']
        ),
    'apache_error': collections.namedtuple('apache_error', [
        'date', 'module', 'pid', 'client_ip', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'syslog': collections.namedtuple('syslog', [
        'date', 'host', 'type', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'fail2ban': collections.namedtuple('fail2ban', [
        'date', 'type', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'rsync': collections.namedtuple('rsync', [
        'date', 'pid', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'pylogs': collections.namedtuple('pylogs', [
        'date', 'type', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'qmail': collections.namedtuple('qmail', [
        'mid', 'message',
        'filepath', 'logtype', 'timestamp']
        ),
    'lastlog': collections.namedtuple('lastlog', [
        'user', 'term', 'stats',
        'filepath', 'logtype', 'timestamp']
        )
}


def l2fp(txt):
    key = base64.b64decode(txt.strip().split()[1].encode('ascii'))
    fp_plain = hashlib.md5(key).hexdigest()
    fp_md5 = ':'.join(a+b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
    fp_plain_sha = hashlib.sha256(key).digest()
    fp_sha256 = base64.b64encode(fp_plain_sha).decode('ascii').rstrip('=')
    return fp_md5, fp_sha256


class NodeThread(threading.Thread):
    def assign(self, json_blob, logtype, xes):
        self.json = json_blob
        self.logtype = logtype
        self.xes = xes

    def run(self):
        global gotindex, config, json_pending
        # print("Pushing %u json objects" % len(json_pending))
        iname = time.strftime("loggy-%Y.%m.%d")
        if not iname in gotindex:
            gotindex[iname] = True
            if not self.xes.indices.exists(index=iname):
                mappings = {}
                for entry in config.options('RawFields'):
                    js = {
                        "_all": {"enabled": True},
                        "properties": {
                            "@timestamp": {"store": True, "type": "date", "format": "yyyy/MM/dd HH:mm:ss"},
                            "@node": {"store": True, "type": "string", "index": "not_analyzed"},
                            "status": {"store": True, "type": "long"},
                            "date": {"store": True, "type": "string", "index": "not_analyzed"},
                            "geo_location": {"type": "geo_point", "geohash": True}
                        }
                    }
                    for field in config.get('RawFields', entry).split(","):
                        x = field.strip()
                        js['properties'][x] = {"store": True, "type": "string", "index": "not_analyzed",
                                               "fields": {"keyword": {"type": "keyword"}}}
                    mappings[entry] = js
                if not DEBUG:
                    res = self.xes.indices.create(index=iname, ignore=400, body={
                        "settings": {
                            "index.mapping.ignore_malformed": True,
                            "number_of_shards": 2,
                            "number_of_replicas": 0
                        },
                        "mappings": mappings
                    })
                else:
                    print(mappings)
                if not 'loggy-indices' in json_pending:
                    json_pending['loggy-indices'] = []
                    last_push['loggy-indices'] = time.time()
                json_pending['loggy-indices'].append({
                    '@node': hostname,
                    'index_created': iname,
                    'logtype': 'loggy-indices',
                    '@timestamp': time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime()),
                    'res': res,
                    'mappings': mappings
                })

        js_arr = []
        for entry in self.json:
            js = entry
            # GeoHash conversion
            if 'geo_lat' in js and 'geo_long' in js:
                try:
                    js['geo_location'] = {
                        "lat": float(js['geo_lat']),
                        "lon": float(js['geo_long'])
                    }
                except:
                    pass
            js['@version'] = 2
            js['@timestamp'] = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
            js['host'] = hostname
            js['@node'] = hostname
            js['@fingerprint'] = FINGERPRINT
            js['@fingerprint_sha'] = FINGERPRINT_SHA
            #             js['@rsa_key_mtime'] = RSA_KEY_MTIME
            # Rogue string sometimes, we don't want that!
            if 'bytes' in js:
                try:
                    js['bytes'] = int(js['bytes'])
                except:
                    js['bytes'] = 0
            if mytags:
                js['@tags'] = mytags
            if 'request' in js and not 'url' in js:
                match = re.match(r"(GET|POST)\s+(.+)\s+HTTP/.+", js['request'])
                if match:
                    js['url'] = match.group(2)
            if 'bytes' in js and isinstance(js['bytes'], str) and js['bytes'].isdigit():
                js['bytes_int'] = int(js['bytes'])

            js_arr.append({
                '_op_type': 'index',
                '_index': iname,
                '_type': self.logtype,
                'doc': js,
                '_source': js
            })

        if len(js_arr) > 0:
            if DEBUG:
                print(js_arr)
            else:
                elasticsearch.helpers.bulk(self.xes, js_arr)
        # except Exception as err:
        # print(err)


def connect_es(config):
    esa = []
    for w in ['primary', 'backup']:
        if w in config['elasticsearch'].keys():
            h = config['elasticsearch'][w]['host']
            p = config['elasticsearch'][w].get('port', 9200)
            s = config['elasticsearch'][w].get('ssl', False)
            u = config['elasticsearch'][w].get('prefix', '')
            esa.append({
                'host': h,
                'port': p,
                'use_ssl': s,
                'url_prefix': u
            })
            print("Using http%s://%s:%u/%s as %s" % ("s" if s else "", h, p, u, w))

    esx = elasticsearch.Elasticsearch(
        esa,
        max_retries=5,
        retry_on_timeout=True
    )
    return esx


def parse_line(path, data):
    global json_pending, config
    for line in (l.rstrip() for l in data.split("\n")):
        m = re.match(r"^<%JSON:([^>%]+)%>\s*(.+)", line)
        if m:
            try:
                # Try normally
                try:
                    js = json.loads(m.group(2))
                # In case \x[..] has been used, try again!
                except:
                    js = json.loads(re.sub(r"\\x..", "?", m.group(2)))
                js['filepath'] = path
                js['timestamp'] = time.time()
                js['logtype'] = m.group(1)
                if not js['logtype'] in json_pending:
                    json_pending[js['logtype']] = []
                    last_push[js['logtype']] = time.time()
                    #  print("got our first valid json as " + js['logtype'] + "!")
                json_pending[js['logtype']].append(js)
            except:
                pass
        else:
            for r in regexes:
                match = regexes[r].match(line)
                if match:
                    js = tuples[r]( filepath=path, logtype=r, timestamp=time.time(), **match.groupdict())
                    if js.logtype not in json_pending:
                        json_pending[js.logtype] = []
                        last_push[js.logtype] = js.timestamp
                    json_pending[r].append(js._asdict())
                    break


class LinuxHandler(watchdog.events.PatternMatchingEventHandler):
    def process(self, event):
        global filehandles, inodes, inodes_path
        path = event.src_path
        if (event.event_type == 'moved') and (path in filehandles):
            #  print("File moved, closing original handle")
            try:
                filehandles[path].close()
            except Exception as err:
                pass
                #  print(err)
            del filehandles[path]
            inode = inodes_path[path]
            del inodes[inode]

        elif (event.event_type == 'modified' or event.event_type == 'created') and (
                path.find(".gz") == -1) and path not in filehandles:
            try:
                idata = os.stat(path)
                inode = idata.st_ino
                if inode not in inodes:
                    # print("Opening: " + path)
                    filehandles[path] = open(path, "r")
                    # print("Started watching %s (%u)" % (path, inode))
                    filehandles[path].seek(0, 2)
                    inodes[inode] = path
                    inodes_path[path] = inode
                    # print(path, filehandles[path])
            except Exception as err:
                #  print(err)
                pass
        elif event.event_type == 'modified' and path in filehandles:
            #  print(path + " was modified")
            rd = 0
            data = ""
            try:
                while True:
                    line = filehandles[path].readline()
                    if not line:
                        break
                    else:
                        rd += len(line)
                        data += line
                #  print("Read %u bytes from %s" % (rd, path))
                parse_line(path, data)
            except Exception as err:
                try:
                    #  print("Could not utilize " + path + ", closing.." + err)
                    filehandles[path].close()
                except Exception as err:
                    #  print(err)
                    pass
                del filehandles[path]
                inode = inodes_path[path]
                del inodes[inode]
        # File deleted? (close handle)
        elif event.event_type == 'deleted':
            if path in filehandles:
                #  print("Closed " + path)
                try:
                    filehandles[path].close()
                except Exception as err:
                    print(err)
                del filehandles[path]
                inode = inodes_path[path]
                del inodes[inode]
                #  print("Stopped watching " + path)

    def on_modified(self, event):
        self.process(event)

    def on_created(self, event):
        self.process(event)

    def on_deleted(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)


def whoami():
    """Returns the FQDN of the box the program runs on"""
    try:
        # Get local hostname (what you see in the terminal)
        local_hostname = socket.gethostname()
        # Get all address info segments for the local host
        canonical_names = [
            address[3] for address in
            socket.getaddrinfo(local_hostname, None, 0, socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
            if address[3]
        ]
        # For each canonical name, see if we find $local_hostname.something.tld, and if so, return that.
        if canonical_names:
            prefix = f"{local_hostname}."
            for name in canonical_names:
                if name.startswith(prefix):
                    return name
            # No match, just return the first occurrence.
            return canonical_names[0]
    except socket.error:
        pass
    # Fall back to socket.getfqdn
    return socket.getfqdn()


if __name__ == "__main__":
    config = yaml.safe_load(open("loggy.yaml").read())
    hostname = whoami()
    if os.path.exists('/etc/dd-agent/datadog.conf'):
        dd_config.read('/etc/dd-agent/datadog.conf')
        if dd_config.has_option('Main', 'tags'):
            mytags = dd_config.get('Main', 'tags')
        if hostname in tag_overrides:
            mytags = tag_overrides[hostname]

    print("Using %s as node name" % hostname)
    if os.path.exists(RSA_KEY):
        with open(RSA_KEY, 'r') as rsa:
            FINGERPRINT, FINGERPRINT_SHA = l2fp(rsa.read())
            print("Identifying as %s" % FINGERPRINT)
    xes = connect_es(config)

    observer = watchdog.observers.Observer()
    for path in config['analyzer']['paths']:
        if os.path.isdir(path):
            observer.schedule(LinuxHandler(), path, recursive=True)
    observer.start()
    try:
        while True:
            for x in json_pending:
                if x not in last_push:
                    last_push[x] = time.time()
                if len(json_pending[x]) > 0 and ((time.time() > (last_push[x] + 15)) or len(json_pending[x]) >= 500):
                    if x not in fp:
                        fp[x] = True
                        #  print("First push for " + x + "!")
                    t = NodeThread()
                    t.assign(json_pending[x], x, xes)
                    t.start()
                    json_pending[x] = []
                    last_push[x] = time.time()
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
