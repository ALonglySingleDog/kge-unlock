#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import math
from pathlib import Path
from typing import List, Tuple
from kge_crypto import KgeError, KgeHeader, HEADER_SIZE, MIX, PERIOD, TEMPLATE, RecoveredKey, fold32, header_a0
from native_transforms import transform

def _fwt(arr: List[float]) -> None:
    n = len(arr)
    step = 1
    while step < n:
        gap = step * 2
        for x in range(0, n, gap):
            for j in range(x, x + step):
                a, b = arr[j], arr[j + step]
                arr[j] = a + b
                arr[j + step] = a - b
        step = gap

def _residue_hist(path, h: KgeHeader, sample_limit=64 * 1024 * 1024):
    a0 = header_a0(h)
    b = h.salt
    hist = [[0] * 256 for _ in range(PERIOD)]
    count = 0
    with open(path, 'rb') as f:
        f.seek(HEADER_SIZE)
        while count < sample_limit:
            ciphertext = f.read(min(1024 * 1024, sample_limit - count))
            if not ciphertext:
                break
            for local, c in enumerate(ciphertext):
                i = count + local
                if h.kind == 2:
                    d = MIX[c] ^ a0[i & 15]
                elif h.kind == 3:
                    d = MIX[c ^ b[i & 15]] ^ fold32(i) ^ a0[i & 15]
                else:
                    d = MIX[c ^ b[(i // PERIOD) & 15]] ^ fold32(i) ^ a0[i & 15]
                hist[i % PERIOD][d] += 1
            count += len(ciphertext)
    return hist, count

def _xor_scores(hist):
    baseline = [sum(hist[r][x] for r in range(16)) for x in range(256)]
    total = sum(baseline)
    if total < 4096:
        raise KgeError('Insufficient audio data for statistical key recovery')
    avg = total / 256.0
    alpha = max(1.0, avg * 0.10)
    logp = [math.log((v + alpha) / (total + 256 * alpha)) for v in baseline]
    ref = logp[:]
    _fwt(ref)
    scores = []
    for h in hist:
        spectrum = list(map(float, h))
        _fwt(spectrum)
        z = [spectrum[j] * ref[j] for j in range(256)]
        _fwt(z)
        scores.append([v / 256.0 for v in z])
    return scores

def _best(scores, r):
    row = scores[r]
    best = max(range(256), key=row.__getitem__)
    second = max((row[i] for i in range(256) if i != best), default=row[best])
    return best, row[best] - second

def _initial_u(scores):
    u = [0] * 17
    u[16] = _best(scores, 16)[0]
    for i in range(1, 16):
        u[i] = u[i - 1] ^ _best(scores, 16 + i)[0]
    return u

def _spanning_seed(scores):
    edges = []
    for r in range(16, PERIOD):
        a, b = r % 17, r % 16
        if a == b:
            continue
        k, margin = _best(scores, r)
        edges.append((margin, r, a, b, k))
    edges.sort(reverse=True)
    parent = list(range(17))
    delta = [0] * 17

    def find(i):
        if parent[i] != i:
            root, d = find(parent[i])
            delta[i] ^= d
            parent[i] = root
        return parent[i], delta[i]

    for _weight, r, a, b, v in edges:
        ra, da = find(a)
        rb, db = find(b)
        if ra != rb:
            parent[ra] = rb
            delta[ra] = da ^ db ^ v
    root, ref = find(0)
    if any(find(i)[0] != root for i in range(17)):
        raise KgeError('Cannot span 17-byte key graph')
    return [find(i)[1] ^ ref for i in range(17)]

def _objective(scores, u):
    return sum(scores[r][u[r % 17] ^ u[r % 16]] for r in range(16, PERIOD))

def _refine(scores, seed, rounds=12):
    u = seed[:]
    for _ in range(rounds):
        changed = False
        for j in range(1, 17):
            neighbors = []
            for r in range(16, PERIOD):
                a, b = r % 17, r % 16
                if a == j and b != j:
                    neighbors.append((r, b))
                elif b == j and a != j:
                    neighbors.append((r, a))
            base = max(range(256), key=lambda v: sum(scores[r][v ^ u[n]] for r, n in neighbors))
            if base != u[j]:
                u[j] = base
                changed = True
        if not changed:
            break
    return u

def _recover_candidate(scores):
    seeds = [_initial_u(scores), _spanning_seed(scores)]
    solutions = [_refine(scores, s) for s in seeds]
    best_u = max(solutions, key=lambda s: _objective(scores, s))
    matches = sum(_best(scores, r)[0] == (best_u[r % 17] ^ best_u[r % 16])
                  for r in range(PERIOD))
    return best_u, matches

def recover_statistical(path, sample_limit=64 * 1024 * 1024) -> Tuple[KgeHeader, RecoveredKey]:
    path = Path(path)
    with path.open('rb') as f:
        h = KgeHeader.parse(f.read(HEADER_SIZE))
    if h.kind not in (2, 3, 4):
        raise KgeError('Unsupported native KGE type')
    hist, n = _residue_hist(path, h, sample_limit)
    scores = _xor_scores(hist)
    u, matches = _recover_candidate(scores)
    a0 = header_a0(h)
    a272 = bytes(a0[i % 16] ^ u[i % 17] ^ u[i % 16] for i in range(PERIOD))
    if transform(h.kind, bytes.fromhex('3885ed92795ff84cb303614116a01d47'),
                 a272, h.salt, encrypt=True) != h.wrapped_template:
        raise KgeError('Candidate key failed native KGE header verification')
    with path.open('rb') as f:
        f.seek(HEADER_SIZE)
        prefix = transform(h.kind, f.read(4096), a272, h.salt, offset=0)
    if prefix.startswith(b'fLaC'):
        codec = 'flac'
    elif prefix.startswith(b'ID3') or (prefix[:1] == b'\xff' and
                                      len(prefix) > 1 and (prefix[1] & 0xe0) == 0xe0):
        codec = 'mp3'
    elif prefix.startswith(b'OggS'):
        codec = 'ogg'
    else:
        raise KgeError('Statistical key does not restore a recognized media header')
    if matches < 32:
        raise KgeError('Statistical key recovery is ambiguous: %d/272 residue shifts agree' % matches)
    return h, RecoveredKey(a272, h.salt)
