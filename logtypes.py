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

import re
import collections

# Patterns for common log types
regexes = {
    "apache_access": re.compile(
        r"(?P<client_ip>[\d\.]+)\s"
        r"(?P<identity>\S*)\s"
        r"(?P<user>\S*)\s"
        r"\[(?P<time_txt>.*?)\]\s"
        r'"(?P<request>.*?)"\s'
        r"(?P<status>\d+)\s"
        r"(?P<bytes>\S*)\s"
        r'"(?P<referer>.*?)"\s'
        r'"(?P<user_agent>.*?)"\s*'
    ),
    "apache_error": re.compile(
        r"\[(?P<date>.*?)\]\s+"
        r"\[(?P<module>.*?)\]\s+"
        r"\[(?P<pid>.*?)\]\s+"
        r"\[client\s+(?P<client_ip>[0-9.]+):\d+\]\s+"
        r"(?P<message>.+)"
    ),
    "syslog": re.compile(
        r"(?P<date>\S+\s+\d+\s+\d+:\d+:\d+)\s+(<[0-9.]+>\s+)?"
        r"(?P<host>\S+)\s+"
        r"(?P<type>\S+):\s+"
        r"(?P<message>.+)"
    ),
    "fail2ban": re.compile(r"(?P<date>\S+ \d+:\d+:[\d,]+)\s+" r"(?P<type>fail2ban\.[^:]+):\s+" r"(?P<message>.+)"),
    "rsync": re.compile(r"(?P<date>\S+ \d+:\d+:[\d,]+)\s+" r"\[(?P<pid>[\S.]+)\]\s+" r"(?P<message>.+)"),
    "pylogs": re.compile(r"(?P<date>\S+ \S+)\s+\[pylog\]\s+" r"\[(?P<type>[\S.]+)\]:\s+" r"(?P<message>.+)"),
    "qmail": re.compile(r"(?P<mid>@[a-f0-9]+)\s+" r"(?P<message>.+)"),
    "lastlog": re.compile(r"USER: (?P<user>([-.a-z0-9]+))\((?P<uid>(\d+))\);\s+T: \[(?P<time_txt>([^]]+))\]; LINE: (?P<term>(pts/\d+|tty\d+|system)); HOST: (?P<client_ip>[0-9a-f:.]+)"),
}

# These names must agree with the regexes above
tuples = {
    "apache_access": collections.namedtuple(
        "apache_access",
        [
            "client_ip",
            "identity",
            "user",
            "time_txt",
            "request",
            "status",
            "bytes",
            "referer",
            "user_agent",
            "filepath",
            "logtype",
            "timestamp",
        ],
    ),
    "apache_error": collections.namedtuple(
        "apache_error", ["date", "module", "pid", "client_ip", "message", "filepath", "logtype", "timestamp"]
    ),
    "syslog": collections.namedtuple("syslog", ["date", "host", "type", "message", "filepath", "logtype", "timestamp"]),
    "fail2ban": collections.namedtuple("fail2ban", ["date", "type", "message", "filepath", "logtype", "timestamp"]),
    "rsync": collections.namedtuple("rsync", ["date", "pid", "message", "filepath", "logtype", "timestamp"]),
    "pylogs": collections.namedtuple("pylogs", ["date", "type", "message", "filepath", "logtype", "timestamp"]),
    "qmail": collections.namedtuple("qmail", ["mid", "message", "filepath", "logtype", "timestamp"]),
    "lastlog": collections.namedtuple("lastlog", ["user", "time_txt", "term", "client_ip", "filepath", "logtype", "timestamp"]),
}
