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
import base64
import hashlib
import elasticsearch
import elasticsearch.helpers
import threading
import socket
import yaml
import logtypes
import typing

# Disable most ES logging, or it'll litter syslog
tracer = logging.getLogger("elasticsearch")
tracer.setLevel(logging.CRITICAL)
tracer.addHandler(logging.FileHandler("loggy.log"))

DEBUG = False
YAML_FILE = "loggy.yaml"
INDEX_PATTERN = "loggy-%Y-%m-%d"  # Name pattern for when creating new indices
MAX_PENDING_DOCS = 250  # If more than 250 pending log entries, push to ES
MAX_IDLE_TIME = 15  # If we waited more than 15 seconds to push entries, push even if < 250 docs.
RSA_KEY = "/etc/ssh/ssh_host_rsa_key.pub"  # RSA public key for SSH. if it exists.
FINGERPRINT = ""
FINGERPRINT_SHA = ""
SUPPORTED_PROVIDERS = ("elasticsearch", "opensearch", )  # Supported database providers to look for in the config


def l2fp(txt: str):
    """public key to md5/sha256 fingerprint"""
    key = base64.b64decode(txt.strip().split()[1].encode("ascii"))
    fp_plain = hashlib.md5(key).hexdigest()
    fp_md5 = ":".join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
    fp_plain_sha = hashlib.sha256(key).digest()
    fp_sha256 = base64.b64encode(fp_plain_sha).decode("ascii").rstrip("=")
    return fp_md5, fp_sha256


def who_am_i():
    """Returns the FQDN of the box the program runs on"""
    try:
        # Get local hostname (what you see in the terminal)
        local_hostname = socket.gethostname()
        # Get all address info segments for the local host
        canonical_names = [
            address[3]
            for address in socket.getaddrinfo(local_hostname, None, 0, socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
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


class NodeThread(threading.Thread):
    """Offloading thread for pushing entries to ES"""
    def __init__(self, log_object: "ElasticLogger"):
        super().__init__()
        self.json = log_object.pending
        self.parent = log_object.parent

    def run(self):
        iname = time.strftime(INDEX_PATTERN)
        if iname not in self.parent.indices:
            self.parent.indices.append(iname)
            if not self.parent.elastic.indices.exists(index=iname):
                mappings = {}
                for name, entry in self.parent.config.get("rawfields").items():
                    map_js: typing.Dict[str, typing.Dict[typing.Union[str, bool]]] = {
                        "_all": {"enabled": True},
                        "properties": {
                            "@timestamp": {"store": True, "type": "date", "format": "yyyy/MM/dd HH:mm:ss"},
                            "@node": {"store": True, "type": "keyword"},
                            "status": {"store": True, "type": "long"},
                            "date": {"store": True, "type": "keyword"},
                            "geo_location": {"type": "geo_point", "geohash": True},
                        },
                    }
                    for field in entry.split(","):
                        x = field.strip()
                        map_js["properties"][x] = {"store": True, "type": "keyword"}
                    mappings[entry] = map_js
                if not DEBUG:
                    self.parent.elastic.indices.create(
                        index=iname,
                        ignore=400,
                        body={
                            "settings": {
                                "index.mapping.ignore_malformed": True,
                                "number_of_shards": 2,
                                "number_of_replicas": 0,
                            },
                            "mappings": mappings,
                        },
                    )
                else:
                    print(mappings)

        js_arr = []
        for js in self.json:
            # GeoHash conversion
            if "geo_lat" in js and "geo_long" in js:
                try:
                    js["geo_location"] = {"lat": float(js["geo_lat"]), "lon": float(js["geo_long"])}
                except ValueError:
                    pass
            js["@version"] = 3
            js["@timestamp"] = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
            js["host"] = self.parent.logger.nodename
            js["@node"] = self.parent.logger.nodename
            if FINGERPRINT:
                js["@fingerprint"] = FINGERPRINT
                js["@fingerprint_sha"] = FINGERPRINT_SHA
            # Rogue string sometimes, we don't want that!
            if "bytes" in js:
                try:
                    js["bytes"] = int(js["bytes"])
                except ValueError:
                    js["bytes"] = 0
            if "request" in js and "url" not in js:
                match = re.match(r"(GET|POST)\s+(.+)\s+HTTP/.+", js["request"])
                if match:
                    js["url"] = match.group(2)
            if "bytes" in js and isinstance(js["bytes"], str) and js["bytes"].isdigit():
                js["bytes_int"] = int(js["bytes"])

            js_arr.append({"_op_type": "index", "_index": iname, "doc": js, "_source": js})

        if len(js_arr) > 0:
            if DEBUG:
                print(js_arr)
            else:
                try:
                    elasticsearch.helpers.bulk(self.parent.elastic, js_arr)
                except elasticsearch.helpers.BulkIndexError as e:
                    print(e)


class LinuxHandler(watchdog.events.PatternMatchingEventHandler):
    """Generic watchdog class, to be consumed and tweaked by Logger below"""

    def __init__(self, parent_logger: "Logger"):
        super().__init__()
        self.logger = parent_logger

    def process(self, event):
        self.logger.process(event)

    def on_modified(self, event):
        self.process(event)

    def on_created(self, event):
        self.process(event)

    def on_deleted(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)


class Logger:
    """Parent logger class for monitoring and reading log changes"""

    def __init__(self, config: dict):
        self.config = config
        self.nodename = who_am_i()
        self.observer = watchdog.observers.Observer()
        self.processor = LinuxHandler(self)
        self.file_handles: typing.Dict[str, typing.TextIO] = {}
        self.inodes: typing.Dict[int, str] = {}
        self.inodes_path: typing.Dict[str, int] = {}
        self.logs = ElasticParent(self)

    def monitor(self, paths):
        for path in paths:
            if os.path.isdir(path):
                self.observer.schedule(self.processor, path, recursive=True)
        self.observer.start()

    def parse_line(self, path, data):
        for line in (line.rstrip() for line in data.split("\n")):
            m = re.match(r"^<%JSON:([^>%]+)%>\s*(.+)", line)
            if m:
                try:
                    # Try normally
                    try:
                        js = json.loads(m.group(2))
                    # In case \x[..] has been used, try again!
                    except json.JSONDecodeError:
                        js = json.loads(re.sub(r"\\x..", "?", m.group(2)))
                    js["filepath"] = path
                    js["timestamp"] = time.time()
                    js["logtype"] = m.group(1)
                    self.logs.append(js["logtype"], js)
                except json.JSONDecodeError:
                    pass
            else:
                for r in logtypes.regexes:
                    match = logtypes.regexes[r].match(line)
                    if match:
                        js = logtypes.tuples[r](filepath=path, logtype=r, timestamp=time.time(), **match.groupdict())
                        self.logs.append(js.logtype, js._asdict())
                        break

    def process(self, event):
        path = event.src_path
        if (event.event_type == "moved") and (path in self.file_handles):
            try:
                self.file_handles[path].close()
            except IOError:
                pass
            del self.file_handles[path]
            inode = self.inodes_path[path]
            del self.inodes[inode]

        elif (
            (event.event_type == "modified" or event.event_type == "created")
            and (path.find(".gz") == -1)
            and path not in self.file_handles
        ):
            try:
                idata = os.stat(path)
                inode = idata.st_ino
                if inode not in self.inodes:
                    # print("Opening: " + path)
                    self.file_handles[path] = open(path, "r")
                    # print("Started watching %s (%u)" % (path, inode))
                    self.file_handles[path].seek(0, 2)
                    self.inodes[inode] = path
                    self.inodes_path[path] = inode
            except IOError:
                pass
        elif event.event_type == "modified" and path in self.file_handles:
            rd = 0
            data = ""
            try:
                while True:
                    line = self.file_handles[path].readline()
                    if not line:
                        break
                    else:
                        rd += len(line)
                        data += line
                self.parse_line(path, data)
            except (IOError, UnicodeDecodeError):
                try:
                    self.file_handles[path].close()
                except IOError:
                    pass
                del self.file_handles[path]
                inode = self.inodes_path[path]
                del self.inodes[inode]
        # File deleted? (close handle)
        elif event.event_type == "deleted":
            if path in self.file_handles:
                try:
                    self.file_handles[path].close()
                except IOError:
                    pass
                del self.file_handles[path]
                inode = self.inodes_path[path]
                del self.inodes[inode]


class ElasticParent:
    def __init__(self, parent):
        self.config = parent.config
        self.logger = parent
        self.loggers = {}
        self.hosts = []
        for provider in SUPPORTED_PROVIDERS:
            if provider in parent.config:
                self.hosts.extend(parent.config[provider].get("hosts", []))
        self.elastic = elasticsearch.Elasticsearch(
            hosts=self.hosts, max_retries=5, retry_on_timeout=True
        )
        self.indices = []

    def append(self, log_type, data):
        if log_type not in self.loggers:
            self.loggers[log_type] = ElasticLogger(self)
        self.loggers[log_type].append(data)

    def types(self):
        for k, v in self.loggers.items():
            yield k, v


class ElasticLogger:
    def __init__(self, parent: ElasticParent):
        self.parent = parent
        self.last_push = time.time()
        self.sequence_id = 0
        self.sequence_time = 0
        self.pending: typing.List[dict] = []

    def append(self, data: dict):
        now = int(time.time())
        # Sequence ID is so we can order atomically in ES.
        data["sequence_id"] = (now * 10000) + self.sequence_id
        # Reset sequence every second if need be
        if self.sequence_time != now:
            self.sequence_time = now
            self.sequence_id = 0
        self.sequence_id += 1
        self.pending.append(data)

    def push_if_needed(self):
        if self.pending:
            now = time.time()
            if now - MAX_IDLE_TIME >= self.last_push or len(self.pending) > MAX_PENDING_DOCS:
                nt = NodeThread(self)
                nt.start()
                self.pending = []
                self.last_push = now


if __name__ == "__main__":
    yml = yaml.safe_load(open(YAML_FILE))
    logger = Logger(yml)

    print("Using %s as node name" % logger.nodename)
    if os.path.exists(RSA_KEY):
        with open(RSA_KEY, "r") as rsa:
            FINGERPRINT, FINGERPRINT_SHA = l2fp(rsa.read())
            print("Identifying as %s" % FINGERPRINT)

    logger.monitor(yml["paths"])

    try:
        while True:
            for t, logs in logger.logs.types():
                logs.push_if_needed()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.observer.stop()
    logger.observer.join()
