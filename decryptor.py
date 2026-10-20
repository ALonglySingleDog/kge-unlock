#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Optional
from kge_crypto import KgeError, KgeHeader, HEADER_SIZE
from key_recovery import recover_automatic_key
from media_metadata import detect_codec, output_basename, read_tags
from media_verify import verify_audio
from native_transforms import transform

def _quality_of(filename: str) -> Optional[str]:
    m = re.search(r'_(LQ|MQ|HQ|SQ|HIRES)(?:_force)?\.kge$', filename, re.I)
    return m.group(1).upper() if m else None

def decrypt_one(input_path: Path):
    src = input_path.expanduser().resolve()
    if not src.is_file():
        raise KgeError('Input file does not exist: %s' % src)
    with src.open('rb') as f:
        header = KgeHeader.parse(f.read(HEADER_SIZE))
    if header.kind not in (2, 3, 4):
        raise KgeError('Unsupported KGE encryption type: %s' % header.kind)
    h, key, method = recover_automatic_key(src)
    if len(key.a272) != 272 or len(key.b16) != 16:
        raise KgeError('Recovered key size mismatch: A=%d B=%d' %
                       (len(key.a272), len(key.b16)))

    temporary = None
    total = 0
    try:
        with tempfile.NamedTemporaryFile('wb', dir=str(src.parent),
                                         prefix='.kge-unlock-', suffix='.tmp',
                                         delete=False) as out:
            temporary = Path(out.name)
            with src.open('rb') as enc:
                enc.seek(HEADER_SIZE)
                while True:
                    data = enc.read(1024 * 1024)
                    if not data:
                        break
                    out.write(transform(h.kind, data, key.a272, key.b16, total))
                    total += len(data)
        if total == 0:
            raise KgeError('Encrypted file has no media data')
        codec = detect_codec(temporary)
        verification = verify_audio(temporary, codec)
        tags = read_tags(temporary)
        quality = _quality_of(src.name)
        filename = output_basename(src, temporary, quality=quality)
        target = src.with_name(filename)
        if target == src:
            raise KgeError('Output path is identical to input path')
        if target.exists():
            raise KgeError('Output file already exists, refused to overwrite: %s' % target)
        os.replace(temporary, target)
        temporary = None
        return {'input': src, 'output': target, 'kind': h.kind,
                'method': method, 'key_a': key.a272.hex(),
                'key_b': key.b16.hex(), 'codec': codec,
                'quality': quality or 'unknown', 'tags': tags,
                'verification': verification, 'bytes': total}
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
