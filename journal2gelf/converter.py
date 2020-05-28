from __future__ import division, absolute_import
from __future__ import print_function
from builtins import next
from builtins import object
import json
import logging

from . import gelfclient
from .reader import Reader


log = logging.getLogger(__name__)
default_exclude_fields = frozenset([
    '__MONOTONIC_TIMESTAMP',
    '_MACHINE_ID',
    '__CURSOR',
    '_SYSTEMD_CGROUP',
    '_AUDIT_SESSION',
    '_CAP_EFFECTIVE',
    '_SYSTEMD_SLICE',
    '_AUDIT_LOGINUID',
    '_SYSTEMD_OWNER_UID',
    '_SOURCE_REALTIME_TIMESTAMP',
    '_SYSTEMD_SESSION',
])


class Converter(object):
    def __init__(self, host, port, exclude_fields=set(), default_excludes=True):
        self.gelf = gelfclient.UdpClient(host, port=port)
        self.exclude_fields = set(exclude_fields)
        if default_excludes:
            self.exclude_fields.update(default_exclude_fields)
        self.debug = False
        self.send = True
        self.lower = True
        self.cursor = None
        self.message_json = False
        self.no_dup_underscore = False
        self.convert_record = convert_record

    def run(self, merge=False, cursor=None):
        j = Reader()

        try:
            next(j)
        except StopIteration:
            log.warning("Journal is empty. Or maybe you don't have permissions to read it.")
        finally:
            j.seek_head()

        if merge:
            if cursor:
                j.seek_cursor(cursor)
                try:
                    next(j)
                except StopIteration:
                    # cursor not found, journal was rotated
                    j.seek_head()
        else:
            j.seek_tail()
            j.get_previous()

        for record in j:
            self.cursor = record['__CURSOR']
            record = self.convert_record(
                record, excludes=self.exclude_fields, lower=self.lower,
                no_dup_underscore=self.no_dup_underscore, message_json=self.message_json)
            if self.send:
                self.gelf.log(**record)
            if self.debug:
                print(json.dumps(record, indent=2))


# See https://www.graylog.org/resources/gelf-2/#specs
# And http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
def convert_record(src, excludes=set(), lower=True, no_dup_underscore=False,
                   message_json=False):
    for k, v in list(src.items()):
        conv = field_converters.get(k)
        if conv:
            try:
                src[k] = conv(v)
            except ValueError:
                pass

    if message_json and src.get('MESSAGE', b'').startswith(b'{"'):
        try:
            src.update({'_'+k: v for k, v in json.loads(src['MESSAGE']).items()})
        except ValueError:  # json.JSONDecodeError inherits ValueError
            pass

    dst = {
        'version': '1.1',
        'host': src.pop('_HOSTNAME', None),
        'short_message': src.pop('MESSAGE', b''),
        'timestamp': src.pop('__REALTIME_TIMESTAMP', None),
        'level': src.pop('PRIORITY', None),
        '_facility': src.get('SYSLOG_IDENTIFIER') or src.get('_COMM')
    }

    for k, v in list(src.items()):
        if k in excludes:
            continue
        if lower:
            k = k.lower()
        if k in system_fields:
            k = '_'+k
        if not no_dup_underscore or k[0] != '_':
            dst['_'+k] = v
        else:
            dst[k] = v
    return dst


def convert_timestamp(value):
    return float(value) / 1000000.0


def convert_monotonic_timestamp(value):
    return convert_timestamp(value[0])


field_converters = {
    '__MONOTONIC_TIMESTAMP': convert_monotonic_timestamp,
    'EXIT_STATUS': int,
    '_AUDIT_LOGINUID': int,
    '_PID': int,
    'COREDUMP_UID': int,
    'COREDUMP_SESSION': int,
    'SESSION_ID': int,
    '_SOURCE_REALTIME_TIMESTAMP': convert_timestamp,
    '_GID': int,
    'INITRD_USEC': int,
    'ERRNO': int,
    'SYSLOG_FACILITY': int,
    '__REALTIME_TIMESTAMP': convert_timestamp,
    '_SYSTEMD_SESSION': int,
    '_SYSTEMD_OWNER_UID': int,
    'COREDUMP_PID': int,
    '_AUDIT_SESSION': int,
    'USERSPACE_USEC': int,
    'PRIORITY': int,
    'KERNEL_USEC': int,
    '_UID': int,
    'SYSLOG_PID': int,
    'COREDUMP_SIGNAL': int,
    'COREDUMP_GID': int,
    '_SOURCE_MONOTONIC_TIMESTAMP': convert_monotonic_timestamp,
    'LEADER': int,
    'CODE_LINE': int
}

system_fields = frozenset([
    '_id',   # actually only _id and _uid are reserved in elasticsearch
    '_uid',  # but for consistency we rename all this fields
    '_gid',
    '_pid',
])
