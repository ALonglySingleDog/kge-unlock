#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from kge_crypto import KgeError, verify_ogg

class Mp3IntegrityError(ValueError):
    pass

def frame_length(data, i):
    if i + 4 > len(data) or data[i] != 0xff or data[i + 1] & 0xe0 != 0xe0:
        return 0
    ver = (data[i + 1] >> 3) & 3
    layer = (data[i + 1] >> 1) & 3
    if ver == 1 or layer != 1:
        return 0
    bitrate = (data[i + 2] >> 4) & 15
    sample = (data[i + 2] >> 2) & 3
    if bitrate in (0, 15) or sample == 3:
        return 0
    rate = (44100, 48000, 32000)[sample]
    if ver == 2:
        rate //= 2
    elif ver == 0:
        rate //= 4
    rates = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128,
             160, 192, 224, 256, 320) if ver == 3 else (
             0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96,
             112, 128, 144, 160)
    kbps = rates[bitrate]
    padding = (data[i + 2] >> 1) & 1
    length = (144000 if ver == 3 else 72000) * kbps // rate + padding
    return length if length >= 24 else 0

def _skip_id3(data):
    if data[:3] != b'ID3':
        return 0
    if len(data) < 10 or data[3] not in (2, 3, 4) or any(x & 128 for x in data[6:10]):
        raise Mp3IntegrityError('Invalid ID3v2 header')
    size = 0
    for b in data[6:10]:
        size = (size << 7) | b
    end = size + 10 + (10 if data[5] & 0x10 else 0)
    if end > len(data):
        raise Mp3IntegrityError('Truncated ID3v2 tag')
    return end

def verify_mp3(path):
    buf = Path(path).read_bytes()
    start = _skip_id3(buf)
    if start == 0 and (len(buf) < 4 or buf[0] != 255):
        raise Mp3IntegrityError('MP3 stream or ID3 header not found')
    head = -1
    for pos in range(start, min(len(buf) - 1024, start + 8192)):
        size = frame_length(buf, pos)
        if size:
            p2 = pos + size
            s2 = frame_length(buf, p2)
            if s2 and frame_length(buf, p2 + s2):
                head = pos
                break
    if head < 0:
        raise Mp3IntegrityError('No three consecutive valid MP3 frames')
    if any(buf[start:head]):
        raise Mp3IntegrityError('Unexpected nonzero data before first MP3 frame')
    p = head
    frames = 0
    while True:
        step = frame_length(buf, p)
        if not step or p + step > len(buf):
            break
        frames += 1
        p += step
    tail = buf[p:]
    if tail.startswith(b'TAG') and len(tail) == 128:
        tail = b''
    elif len(tail) <= 8192 and not tail.strip(b'\x00'):
        tail = b''
    if tail:
        raise Mp3IntegrityError('Broken MP3 frame chain at %d of %d bytes' % (p, len(buf)))
    if frames < 3:
        raise Mp3IntegrityError('Insufficient valid MP3 frames')
    return frames, len(buf)

class FlacIntegrityError(ValueError):
    pass

def crc8(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ (0x07 if c & 0x80 else 0)) & 255
    return c

def crc16(data):
    c = 0
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ (0x8005 if c & 0x8000 else 0)) & 65535
    return c

def _frame_header_length(data, pos):
    if pos + 8 > len(data) or data[pos] != 255 or (data[pos + 1] & 0xFE) != 0xF8:
        return 0
    b2, b3 = data[pos + 2], data[pos + 3]
    bs, rate = b2 >> 4, b2 & 15
    ch, depth = b3 >> 4, (b3 >> 1) & 7
    if bs == 0 or rate == 15 or ch > 10 or depth in (3, 7) or b3 & 1:
        return 0
    p = pos + 4
    first = data[p]
    if first & 0x80 == 0:
        chars = 1
    elif (first & 0xE0) == 0xC0:
        chars = 2
    elif (first & 0xF0) == 0xE0:
        chars = 3
    elif (first & 0xF8) == 0xF0:
        chars = 4
    elif (first & 0xFC) == 0xF8:
        chars = 5
    elif (first & 0xFE) == 0xFC:
        chars = 6
    elif first == 0xFE:
        chars = 7
    else:
        return 0
    if p + chars + 5 > len(data):
        return 0
    if any((data[p + j] & 0xC0) != 0x80 for j in range(1, chars)):
        return 0
    p += chars
    if bs == 6:
        p += 1
    elif bs == 7:
        p += 2
    if rate == 12:
        p += 1
    elif rate in (13, 14):
        p += 2
    if p >= len(data):
        return 0
    return p + 1 - pos if crc8(data[pos:p]) == data[p] else 0

def verify_flac(path):
    buf = Path(path).read_bytes()
    if len(buf) < 64 or buf[:4] != b'fLaC':
        raise FlacIntegrityError('FLAC signature or length invalid')
    p = 4
    streaminfo = False
    for i in range(128):
        if p + 4 > len(buf):
            raise FlacIntegrityError('FLAC metadata truncated')
        first = buf[p]
        last = bool(first & 0x80)
        typ = first & 0x7f
        length = int.from_bytes(buf[p + 1:p + 4], 'big')
        if i == 0:
            if typ != 0 or length != 34:
                raise FlacIntegrityError('FLAC STREAMINFO malformed')
            streaminfo = True
        p += 4 + length
        if p > len(buf):
            raise FlacIntegrityError('FLAC metadata overruns file')
        if last:
            break
    else:
        raise FlacIntegrityError('FLAC metadata last-block marker missing')
    if p >= len(buf):
        raise FlacIntegrityError('FLAC audio data missing')
    starts = []
    i = p
    while i < len(buf) - 7:
        j = buf.find(b'\xff', i)
        if j < 0:
            break
        if _frame_header_length(buf, j):
            starts.append(j)
        i = j + 1
    if not starts or starts[0] != p:
        raise FlacIntegrityError('FLAC first frame header CRC8 invalid')
    good = []
    for n, start in enumerate(starts):
        following = starts[n + 1] if n + 1 < len(starts) else len(buf)
        if following - start < 12:
            continue
        check = int.from_bytes(buf[following - 2:following], 'big')
        if crc16(buf[start:following - 2]) == check:
            good.append((start, following))
    if not good and len(starts) < 20000:
        for n, start in enumerate(starts):
            for end in starts[n + 2:n + 8] + ([len(buf)] if n + 1 == len(starts) else []):
                if end - start > 16 and crc16(buf[start:end - 2]) == int.from_bytes(buf[end - 2:end], 'big'):
                    good.append((start,end))
                    break
    if not good:
        raise FlacIntegrityError('FLAC frame CRC16 mismatch')
    chain = {a: b for a, b in good}
    cursor = p
    count = 0
    while cursor in chain:
        cursor = chain[cursor]
        count += 1
    if cursor != len(buf):
        raise FlacIntegrityError('FLAC frame coverage incomplete: %d/%d bytes' % (cursor, len(buf)))
    return count, len(buf)

def verify_audio(path: Path, codec: str) -> str:
    if codec in ('ogg', 'opus', 'vorbis'):
        pages, length = verify_ogg(path)
        if length != path.stat().st_size:
            raise KgeError('Ogg pages do not cover whole file')
        return '%d Ogg pages with valid CRC' % pages
    if codec == 'mp3':
        count, length = verify_mp3(path)
        return '%d complete MP3 frames' % count
    if codec == 'flac':
        count, length = verify_flac(path)
        return '%d FLAC frames with valid CRC8/CRC16' % count
    raise KgeError('Unknown decrypted audio format: '+codec)
