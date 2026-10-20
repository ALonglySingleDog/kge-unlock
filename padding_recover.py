#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from kge_crypto import KgeError, KgeHeader, HEADER_SIZE, MIX, PERIOD, XorConstraints, RecoveredKey, fold32, header_a0
from native_transforms import transform

def _intermediate(h: KgeHeader, c: int, i: int, a0: bytes) -> int:
    if h.kind == 2:
        return MIX[c] ^ a0[i % 16]
    if h.kind == 3:
        b = h.salt[i % 16]
    elif h.kind == 4:
        b = h.salt[(i // PERIOD) % 16]
    else:
        raise KgeError('Unsupported kind: %d' % h.kind)
    return MIX[c ^ b] ^ fold32(i) ^ a0[i % 16]

def _candidate(h, residual, start):
    solver = XorConstraints(17)
    for i in range(start, start + PERIOD):
        if not solver.add(i % 17, i % 16, residual[i]):
            return None
    root0, bias0 = solver.find(0)
    roots = [solver.find(i) for i in range(17)]
    if len({root for root, _ in roots}) != 1:
        return None
    u = [delta ^ bias0 for _, delta in roots]
    a0 = header_a0(h)
    v = [a0[i] ^ u[i] for i in range(16)]
    a = bytes(u[i % 17] ^ v[i % 16] for i in range(PERIOD))
    return a

def recover_padding(src, scan_bytes=1024 * 1024):
    with open(src, 'rb') as f:
        h = KgeHeader.parse(f.read(HEADER_SIZE))
        encrypted = f.read(scan_bytes)
    if h.kind not in (2, 3, 4):
        raise KgeError('Unsupported KGE type')
    if len(encrypted) < PERIOD * 4:
        raise KgeError('Audio body too short for zero-padding recovery')
    a0 = header_a0(h)
    residual = bytes(_intermediate(h, c, i, a0) for i, c in enumerate(encrypted))
    active = None
    threshold = PERIOD * 2
    for i in range(len(residual) - PERIOD):
        equal = residual[i] == residual[i + PERIOD]
        if equal and active is None:
            active = i
        if not equal or i == len(residual) - PERIOD - 1:
            if active is not None and i - active >= threshold:
                start = active + PERIOD
                a = _candidate(h, residual, start)
                if a is not None:
                    sample = transform(h.kind, encrypted[:min(256, len(encrypted))], a, h.salt,
                                       offset=0, encrypt=False)
                    if sample.startswith(b'fLaC'):
                        return h, RecoveredKey(a, h.salt)
                    if sample.startswith(b'ID3') or (len(sample) > 2 and sample[0] == 255 and
                                                        sample[1] & 0xe0 == 0xe0):
                        return h, RecoveredKey(a, h.salt)
            active = None
    raise KgeError('No recoverable zero-padded FLAC/MP3 region in scanned encrypted data')
