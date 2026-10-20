#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from kge_crypto import MIX, fold32

def transform(kind: int, data: bytes, key_a: bytes, key_b: bytes = b'',
              offset: int = 0, encrypt: bool = False) -> bytes:
    if kind not in (2, 3, 4):
        raise ValueError('supported native kinds: 2, 3, 4')
    if not key_a:
        raise ValueError('key_a must be nonempty')
    if kind in (3, 4) and not key_b:
        raise ValueError('key_b must be nonempty for kind 3/4')
    if offset < 0:
        raise ValueError('offset must be >= 0')
    out = bytearray(len(data))
    na = len(key_a)
    nb = len(key_b)
    for j, value in enumerate(data):
        i = offset + j
        a = key_a[i % na]
        if kind == 2:
            out[j] = MIX[value ^ a] if encrypt else MIX[value] ^ a
        else:
            b = key_b[i % nb] if kind == 3 else key_b[(i // na) % nb]
            f = fold32(i)
            out[j] = (MIX[value ^ f ^ a] ^ b) if encrypt else (MIX[value ^ b] ^ a ^ f)
    return bytes(out)
