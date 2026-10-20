#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Dict, List, Tuple
from kge_crypto import KgeError, KgeHeader, HEADER_SIZE, MIX, XorConstraints, RecoveredKey, fold32, ogg_crc, header_a0

def first_page_plain(h: KgeHeader, cipher: bytes, u: List[int]) -> bytes:
    a0 = header_a0(h)
    def value(i, c):
        if h.kind == 2:
            base = MIX[c]
        elif h.kind == 3:
            base = MIX[c ^ h.salt[i % len(h.salt)]] ^ fold32(i)
        else:
            base = MIX[c ^ h.salt[(i // 272) % len(h.salt)]] ^ fold32(i)
        return base ^ a0[i % 16] ^ u[i % 17] ^ u[i % 16]
    return bytes(value(i, c) for i, c in enumerate(cipher))

def known_first(codec: str, channels: int) -> Dict[int, int]:
    if codec == 'vorbis':
        length = 58
        signature = b'\x01vorbis'
        known = {26: 1, 27: 30, 39: channels, 57: 1}
        known.update({i: 0 for i in range(35, 39)})
    elif codec == 'opus':
        length = 47
        signature = b'OpusHead'
        known = {26: 1, 27: 19, 36: 1, 37: channels, 46: 0}
    else:
        raise ValueError('Unknown Ogg codec')
    known.update({i: b for i, b in enumerate(b'OggS\x00\x02')})
    known.update({i: 0 for i in range(6, 14)})
    known.update({i: 0 for i in range(18, 22)})
    known.update({28 + i: b for i, b in enumerate(signature)})
    return known

def _solve_crc_equations(columns: List[int], right: int) -> int:
    n = len(columns)
    rows = [sum((((col >> bit) & 1) << j) for j, col in enumerate(columns))
            | (((right >> bit) & 1) << n) for bit in range(32)]
    pivot_rows = []
    next_row = 0
    for j in range(n):
        pivot = next((k for k in range(next_row, 32) if rows[k] & (1 << j)), None)
        if pivot is None:
            raise KgeError('Insufficient first-page CRC constraints for unique key')
        rows[next_row], rows[pivot] = rows[pivot], rows[next_row]
        for k in range(32):
            if k != next_row and rows[k] & (1 << j):
                rows[k] ^= rows[next_row]
        pivot_rows.append(next_row)
        next_row += 1
    for row in rows:
        if (row & ((1 << n) - 1)) == 0 and row >> n:
            raise KgeError('Contradictory Ogg CRC constraints')
    result = 0
    for j, row_index in enumerate(pivot_rows):
        if (rows[row_index] >> n) & 1:
            result |= 1 << j
    return result

def _derive(h: KgeHeader, ciphertext: bytes, codec: str, channels: int) -> RecoveredKey:
    required = 58 if codec == 'vorbis' else 47
    if len(ciphertext) < required:
        raise KgeError('KGE payload too short for %s page' % codec)
    ciphertext = ciphertext[:required]
    a0 = header_a0(h)

    def intermediate(i):
        c = ciphertext[i]
        if h.kind == 2:
            return MIX[c] ^ a0[i % 16]
        b = h.salt[i % 16] if h.kind == 3 else h.salt[(i // 272) % 16]
        return MIX[c ^ b] ^ fold32(i) ^ a0[i % 16]

    known = known_first(codec, channels)
    solver = XorConstraints(17)
    for i, p in known.items():
        if not solver.add(i % 17, i % 16, intermediate(i) ^ p):
            raise KgeError('Inconsistent known %s header' % codec)
    # The global XOR gauge on all U variables cancels out. Fix U[0]=0.
    roots = [solver.find(i) for i in range(17)]
    zero_root, zero_delta = roots[0]
    free_roots = sorted({root for root, _ in roots} - {zero_root})
    u = [(delta ^ (zero_delta if root == zero_root else 0))
         for root, delta in roots]

    def checksum_syndrome(u_values):
        page = first_page_plain(h, ciphertext, u_values)
        return ogg_crc(page) ^ int.from_bytes(page[22:26], 'little')

    if free_roots:
        baseline = checksum_syndrome(u)
        columns: List[int] = []
        for root in free_roots:
            for bit in range(8):
                altered = [v ^ ((1 << bit) if r == root else 0)
                           for (r, _), v in zip(roots, u)]
                columns.append(checksum_syndrome(altered) ^ baseline)
        solution = _solve_crc_equations(columns, baseline)
        for j, root in enumerate(free_roots):
            byte = (solution >> (j * 8)) & 255
            u = [value ^ (byte if r == root else 0)
                 for (r, _), value in zip(roots, u)]

    page = first_page_plain(h, ciphertext, u)
    if page[:6] != b'OggS\x00\x02' or int.from_bytes(page[22:26], 'little') != ogg_crc(page):
        raise KgeError('Invalid first Ogg page or CRC')
    for i, p in known.items():
        if page[i] != p:
            raise KgeError('Ogg identification mismatch at %d' % i)
    if codec == 'vorbis':
        rate = int.from_bytes(page[40:44], 'little')
        if not (8000 <= rate <= 384000):
            raise KgeError('Vorbis sample rate is out of range')
        blocksize = page[56]
        if not (6 <= (blocksize & 15) <= (blocksize >> 4) <= 13):
            raise KgeError('Invalid Vorbis block size')
    else:
        rate = 48000  # Opus decoding clock; header input sample rate is only a hint.
    v = [a0[i] ^ u[i] for i in range(16)]
    a272 = bytes(u[i % 17] ^ v[i % 16] for i in range(272))
    if a272[:16] != a0:
        raise KgeError('Recovered key failed header consistency check')
    return RecoveredKey(a272, h.salt)

def recover_ogg(path) -> Tuple[KgeHeader, RecoveredKey]:
    with open(path, 'rb') as f:
        header = KgeHeader.parse(f.read(HEADER_SIZE))
        enc = f.read(58)
    if header.kind not in (2, 3, 4):
        raise KgeError('Unsupported KGE cipher type %d' % header.kind)
    failures = []
    for codec in ('vorbis', 'opus'):
        for channel in range(1, 9):
            try:
                return header, _derive(header, enc, codec, channel)
            except (KgeError, ValueError) as err:
                failures.append(str(err))
    raise KgeError('Cannot recover Ogg first-page key; input may be MP3/FLAC or another key derivation')
