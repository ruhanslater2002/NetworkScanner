"""Static configuration shared across the NetScan package."""

from __future__ import annotations

VERSION = "2.2.0"
APP_NAME = "NetScan"
APP_TAGLINE = "network host discovery"

# ---------------------------------------------------------------------------
# Port selection
# ---------------------------------------------------------------------------
#: Sensible default probe set. Covers the services most often exposed on
#: workstations, servers, routers and lab equipment.
TOP_PORTS: tuple[int, ...] = (
    21,  # ftp
    22,  # ssh
    23,  # telnet
    25,  # smtp
    53,  # dns
    80,  # http
    81,  # http-alt
    110,  # pop3
    111,  # rpcbind
    135,  # msrpc
    139,  # netbios-ssn
    143,  # imap
    443,  # https
    445,  # microsoft-ds
    515,  # printer
    554,  # rtsp
    587,  # submission
    631,  # ipp
    873,  # rsync
    993,  # imaps
    995,  # pop3s
    1080,  # socks
    1433,  # ms-sql
    1521,  # oracle
    2049,  # nfs
    2181,  # zookeeper
    2375,  # docker
    3000,  # dev server
    3306,  # mysql
    3389,  # rdp
    5060,  # sip
    5432,  # postgres
    5555,  # adb
    5601,  # kibana
    5900,  # vnc
    5985,  # winrm
    6379,  # redis
    8000,  # http-alt
    8008,  # http-alt
    8080,  # http-proxy
    8081,  # http-alt
    8443,  # https-alt
    8888,  # http-alt
    9000,  # http-alt
    9090,  # prometheus
    9100,  # printer
    9200,  # elasticsearch
    27017,  # mongodb
)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------
#: Refuse to expand a target expression larger than this. Keeps accidental
#: ``--target 10.0.0.0/8`` runs from melting the machine.
MAX_TARGETS = 65_536

#: Prefix used when the local network cannot be detected precisely.
LOCAL_PREFIX = 24

# ---------------------------------------------------------------------------
# Authorised load testing
# ---------------------------------------------------------------------------
#: Hard ceiling for a single load test. Long runs are possible, but the
#: operator has to opt in deliberately rather than by mistyping a duration.
MAX_STRESS_DURATION = 600.0

#: Hard ceiling for concurrent request workers. Beyond this a single host
#: stops being a useful test and starts being an accidental outage.
MAX_STRESS_CONCURRENCY = 512

#: Hard ceiling for the request rate, in requests per second.
MAX_STRESS_RATE = 50_000.0

#: UDP payload ceiling that keeps datagrams inside a normal Ethernet MTU.
MAX_STRESS_PAYLOAD = 1_400

#: Conservative default pacing so a first run never saturates a link.
DEFAULT_STRESS_RATE = 100.0
