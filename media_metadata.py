#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import re
import struct
import unicodedata
from pathlib import Path
from typing import Dict, Iterator

MAX_TAGS = 8 * 1024 * 1024

INVALID_WINDOWS = '<>:"/\\|?*'

RESERVED = {'CON', 'PRN', 'AUX', 'NUL'} | {'COM%d' % n for n in range(1, 10)} | {'LPT%d' % n for n in range(1, 10)}

def detect_codec(filename) -> str:
    with open(filename, 'rb') as f:
        buf = f.read(16)
    if buf.startswith(b'OggS'):
        for pkt in iter_ogg_packets(filename, max_bytes=512 * 1024):
            if pkt.startswith(b'\x01vorbis'):
                return 'vorbis'
            if pkt.startswith(b'OpusHead'):
                return 'opus'
            break
        return 'ogg'
    if buf.startswith(b'fLaC'):
        return 'flac'
    if buf.startswith(b'ID3') or (len(buf) >= 2 and buf[0] == 255 and (buf[1] & 0xe0) == 0xe0):
        return 'mp3'
    return 'unknown'

def iter_ogg_packets(path, max_bytes=MAX_TAGS) -> Iterator[bytes]:
    packet = bytearray()
    with open(path, 'rb') as f:
        while f.tell() < max_bytes:
            head = f.read(27)
            if not head:
                return
            if len(head) != 27 or head[:4] != b'OggS' or head[4] != 0:
                raise ValueError('Invalid Ogg page')
            segments = f.read(head[26])
            if len(segments) != head[26]:
                raise ValueError('Truncated Ogg segment table')
            blob = f.read(sum(segments))
            if len(blob) != sum(segments):
                raise ValueError('Truncated Ogg page body')
            offset = 0
            for size in segments:
                packet.extend(blob[offset:offset + size])
                offset += size
                if len(packet) > max_bytes:
                    raise ValueError('Ogg packet larger than safe metadata limit')
                if size < 255:
                    yield bytes(packet)
                    packet.clear()

def _read_comments(raw: bytes) -> Dict[str, str]:
    def u32(offset):
        if offset + 4 > len(raw):
            raise ValueError('Truncated Vorbis comments')
        return struct.unpack_from('<I', raw, offset)[0]
    pos = 0
    vendor_len = u32(pos)
    pos += 4
    if vendor_len > MAX_TAGS or pos + vendor_len > len(raw):
        raise ValueError('Invalid vendor length')
    pos += vendor_len
    count = u32(pos)
    pos += 4
    tags: Dict[str, str] = {}
    for _ in range(min(count, 10000)):
        length = u32(pos)
        pos += 4
        if length > MAX_TAGS or pos + length > len(raw):
            raise ValueError('Invalid comment length')
        key_value = raw[pos:pos + length].decode('utf-8', errors='replace')
        pos += length
        if '=' in key_value:
            key, value = key_value.split('=', 1)
            key = key.strip().upper()
            value = value.strip()
            if key and value and key not in tags:
                tags[key] = value
    return tags

def _ogg_tags(path) -> Dict[str, str]:
    for i, packet in enumerate(iter_ogg_packets(path)):
        if packet.startswith(b'\x03vorbis'):
            return _read_comments(packet[7:])
        if packet.startswith(b'OpusTags'):
            return _read_comments(packet[8:])
        if i >= 6:
            break
    return {}

def _flac_tags(path) -> Dict[str, str]:
    with open(path, 'rb') as f:
        if f.read(4) != b'fLaC':
            return {}
        while f.tell() < MAX_TAGS:
            head = f.read(4)
            if len(head) < 4:
                break
            is_last = bool(head[0] & 0x80)
            typ = head[0] & 0x7f
            size = int.from_bytes(head[1:], 'big')
            if size > MAX_TAGS:
                break
            if typ == 4:
                return _read_comments(f.read(size))
            f.seek(size, 1)
            if is_last:
                break
    return {}

def _id3_text(frame: bytes) -> str:
    if not frame:
        return ''
    encoding = {0: 'latin-1', 1: 'utf-16', 2: 'utf-16-be', 3: 'utf-8'}.get(frame[0], 'utf-8')
    text = frame[1:].decode(encoding, errors='replace')
    return text.split('\x00', 1)[0].strip()

def _mp3_tags(path) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    with open(path, 'rb') as f:
        head = f.read(10)
        if len(head) == 10 and head[:3] == b'ID3' and head[3] in (3, 4):
            ver = head[3]
            size = 0
            for b in head[6:10]:
                if b & 0x80:
                    return tags
                size = (size << 7) | b
            if size > MAX_TAGS:
                return tags
            end = 10 + size
            while f.tell() + 10 <= end:
                fh = f.read(10)
                if len(fh) < 10 or fh[:4] == b'\0' * 4:
                    break
                name = fh[:4].decode('ascii', errors='ignore')
                if ver == 4:
                    if any(x & 0x80 for x in fh[4:8]):
                        break
                    length = 0
                    for b in fh[4:8]:
                        length = (length << 7) | b
                else:
                    length = int.from_bytes(fh[4:8], 'big')
                if length < 0 or length > MAX_TAGS or f.tell() + length > end:
                    break
                data = f.read(length)
                mapped = {'TIT2': 'TITLE', 'TPE1': 'ARTIST', 'TALB': 'ALBUM'}.get(name)
                if mapped:
                    value = _id3_text(data)
                    if value:
                        tags[mapped] = value
        f.seek(0, os.SEEK_END)
        if f.tell() >= 128:
            f.seek(-128, os.SEEK_END)
            raw = f.read(128)
            if raw.startswith(b'TAG'):
                for key, part in [('TITLE', raw[3:33]), ('ARTIST', raw[33:63]), ('ALBUM', raw[63:93])]:
                    if key not in tags:
                        decoded = part.rstrip(b'\0 ').decode('gb18030', errors='replace').strip()
                        if decoded:
                            tags[key] = decoded
    return tags

def read_tags(path) -> Dict[str, str]:
    codec = detect_codec(path)
    try:
        if codec in ('vorbis', 'opus', 'ogg'):
            return _ogg_tags(path)
        if codec == 'flac':
            return _flac_tags(path)
        if codec == 'mp3':
            return _mp3_tags(path)
    except (ValueError, UnicodeError, OSError, struct.error):
        return {}
    return {}

def safe_windows_component(text: str, max_length: int = 140) -> str:
    text = unicodedata.normalize('NFC', text or '')
    text = ''.join('_' if ch in INVALID_WINDOWS or ord(ch) < 32 else ch for ch in text)
    text = re.sub(r'\s+', ' ', text).strip(' .')
    if not text:
        return 'unknown'
    if text.split('.')[0].upper() in RESERVED:
        text = '_' + text
    return text[:max_length].rstrip(' .') or 'unknown'

def output_basename(src, decrypted_path, quality=None):
    codec = detect_codec(decrypted_path)
    ext = {'vorbis': '.ogg', 'opus': '.opus', 'ogg': '.ogg',
           'flac': '.flac', 'mp3': '.mp3'}.get(codec)
    if ext is None:
        raise ValueError('Unknown decrypted media format: refusing extension guess')
    stem = Path(src).stem
    tags = read_tags(decrypted_path)
    artist = tags.get('ARTIST') or tags.get('ALBUMARTIST') or tags.get('PERFORMER')
    title = tags.get('TITLE')
    if artist and title:
        basename = '%s - %s' % (artist, title)
    elif title:
        basename = title
    else:
        basename = stem + '.dec'
    if quality:
        basename += ' [%s]' % quality
    return safe_windows_component(basename, 220 - len(ext)) + ext
