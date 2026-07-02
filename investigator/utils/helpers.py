"""Helper utilities."""
import re
import socket
from urllib.parse import urlparse


def sanitize_filename(name):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name).strip("_")


def resolve_target(target):
    parsed = urlparse(target)
    host = parsed.hostname or target
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def parse_targets(raw):
    return [resolve_target(t.strip()) for t in raw.split(",") if t.strip()]

