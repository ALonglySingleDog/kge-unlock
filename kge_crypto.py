#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple

MAGIC = bytes.fromhex('7cd532eb86027f4ba8afa68e0fff9914')

TEMPLATE = bytes.fromhex('3885ed92795ff84cb303614116a01d47')

HEADER_SIZE = 1024

MIX = bytes(x ^ ((x & 0x0f) << 4) for x in range(256))

OGG_CRC_POLY = 0x04C11DB7

def _crc_table() -> Tuple[int, ...]:
    result = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ (OGG_CRC_POLY if r & 0x80000000 else 0)) & 0xffffffff
        result.append(r)
    return tuple(result)

_CRC_TABLE = _crc_table()

def ogg_crc(page: bytes) -> int:
    if len(page) < 27:
        raise ValueError('Ogg page is too short')
    crc = 0
    for i, value in enumerate(page):
        if 22 <= i < 26:
            value = 0
        crc = ((crc << 8) ^ _CRC_TABLE[((crc >> 24) ^ value) & 255]) & 0xffffffff
    return crc

def fold32(offset: int) -> int:
    x = offset & 0xffffffff
    return (x ^ (x >> 8) ^ (x >> 16) ^ (x >> 24)) & 255

class KgeError(ValueError):
    pass


@dataclass(frozen=True)
class RecoveredKey:
    a272: bytes
    b16: bytes

@dataclass(frozen=True)
class KgeHeader:
    magic: bytes
    size: int
    kind: int
    flags: int
    wrapped_template: bytes
    salt: bytes
    reserved_nonzero: int

    @classmethod
    def parse(cls, header: bytes) -> 'KgeHeader':
        if len(header) != HEADER_SIZE:
            raise KgeError('KGE header truncated (expected 1024 bytes)')
        if header[:16] != MAGIC:
            raise KgeError('KGE magic mismatch')
        size, kind, flags = struct.unpack_from('<III', header, 16)
        if size != HEADER_SIZE:
            raise KgeError('unsupported KGE header size: %d' % size)
        return cls(header[:16], size, kind, flags, header[28:44],
                   header[44:60], sum(x != 0 for x in header[60:]))

class XorConstraints:

    def __init__(self, size: int):
        self.parent = list(range(size))
        self.delta = [0] * size

    def find(self, i: int) -> Tuple[int, int]:
        if self.parent[i] != i:
            r, x = self.find(self.parent[i])
            self.delta[i] ^= x
            self.parent[i] = r
        return self.parent[i], self.delta[i]

    def add(self, a: int, b: int, value: int) -> bool:
        ra, xa = self.find(a)
        rb, xb = self.find(b)
        if ra == rb:
            return (xa ^ xb) == value
        self.parent[ra] = rb
        self.delta[ra] = xa ^ xb ^ value
        return True

def verify_ogg(path) -> Tuple[int, int]:
    pages = total = 0
    with open(path, 'rb') as f:
        while True:
            head = f.read(27)
            if not head:
                break
            if len(head) != 27 or head[:4] != b'OggS' or head[4] != 0:
                raise KgeError('invalid Ogg page header at offset %d' % total)
            segs = f.read(head[26])
            if len(segs) != head[26]:
                raise KgeError('truncated Ogg segment table at %d' % total)
            payload_size = sum(segs)
            payload = f.read(payload_size)
            if len(payload) != payload_size:
                raise KgeError('truncated Ogg payload at %d' % total)
            page = head + segs + payload
            expected = int.from_bytes(head[22:26], 'little')
            actual = ogg_crc(page)
            if expected != actual:
                raise KgeError('Ogg CRC mismatch on page %d (offset %d)' % (pages, total))
            total += len(page)
            pages += 1
    if pages == 0:
        raise KgeError('no Ogg pages')
    return pages, total

PERIOD = 272

def header_a0(header: KgeHeader) -> bytes:
    k = header.kind
    if k == 2:
        return bytes(MIX[header.wrapped_template[i]] ^ TEMPLATE[i] for i in range(16))
    if k == 3:
        return bytes(MIX[header.wrapped_template[i] ^ header.salt[i]] ^ TEMPLATE[i] ^ fold32(i)
                     for i in range(16))
    if k == 4:
        return bytes(MIX[header.wrapped_template[i] ^ header.salt[0]] ^ TEMPLATE[i] ^ fold32(i)
                     for i in range(16))
    raise KgeError('Unsupported native cipher type %d' % k)
