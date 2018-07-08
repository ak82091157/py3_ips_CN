# -*- coding: utf-8 -*-

import os
import socket
import struct
try:
    import mmap
except ImportError:
    mmap = None

__all__ = ['IPv4IPSDatabase', 'find']

_unpack_V = lambda b: struct.unpack("<i", b)[0]


def _unpack_C(b):
    if isinstance(b, int):
        return b
    return struct.unpack("B", b)[0]


datfile = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "zzipsdb.dat")


class IPv4IPSDatabase(object):
    """Database for search IPv4 address.

    The 17mon dat file format in bytes::

        -----------
        | 8 bytes |                     <- dat version (string)
        -----------------
        | 256 * 4 bytes |               <- first ip number index (int)
        -----------------------
        | offset - 1020 bytes |         <- ip index (32-bit packed binary format, 32-bit packed binary format, int, int, int)
        -----------------------
        |    data  storage    |
        -----------------------
    """

    def __init__(self, filename=None, use_mmap=True):
        if filename is None:
            filename = datfile
        with open(filename, 'rb') as f:
            if use_mmap and mmap is not None:
                buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            else:
                buf = f.read()
                use_mmap = False

        self._use_mmap = use_mmap
        self._buf = buf

        self.__version__ = "1.0.0"
        self.version = struct.unpack("<8s", self._buf[:8])[0]
        self._is_closed = False

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self._use_mmap:
            self._buf.close()
        self._is_closed = True

    def _lookup_ipv4(self, ip):
        nip = socket.inet_aton(ip)

        # first IP number
        fip = bytearray(nip)[0]
        # 4 + (fip - 1) * 4
        fip_offset = fip * 4 + 8

        # position in the index block
        count = _unpack_V(self._buf[fip_offset:fip_offset + 4])
        if count == -1:
            return "未知"

        max_pos = (len(self._buf) - 1032) // 20
        # 获取下个Ip头的索引
        for i in range(fip + 1, 256):
            n_count = _unpack_V(self._buf[i * 4 + 8:i * 4 + 8 + 4])
            if n_count is not -1:
                break
            n_count = max_pos

        _sip = lambda pos: self._buf[pos * 20 + 1032: pos * 20 + 1032 + 4]
        _eip = lambda pos: self._buf[pos * 20 + 1032 + 4: pos * 20 + 1032 + 4 + 4]
        # 查找IP地址所属运营商
        offset = -1
        while count < n_count:
            # strartip <= 目标Ip <= endip
            if _sip(count) <= nip <= _eip(count):
                offset = count
                break
            elif _sip(n_count) <= nip <= _eip(n_count):
                offset = n_count
                break
            else:
                mid = (count + n_count) // 2
                if _sip(mid) <= nip <= _eip(mid):
                    offset = mid
                    break
                elif _sip(mid) > nip:
                    n_count = mid
                else:
                    count = mid + 1
        if offset == -1:
            return "未知"
        else:
            ips = struct.unpack("<i", self._buf[
                offset * 20 + 1032 + 8: offset * 20 + 1032 + 8 + 4])[0]
            if ips == 100025:
                return "中国移动"
            elif ips == 100017:
                return "中国电信"
            elif ips == 100026:
                return "中国联通"

    def find(self, ip):
        if self._is_closed:
            raise ValueError('I/O operation on closed dat file')

        return self._lookup_ipv4(ip)


def find(ip):
    # keep find for compatibility
    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        return

    with IPv4IPSDatabase() as db:
        return db.find(ip)


if __name__ == '__main__':
    print(find('223.242.2.1'))
