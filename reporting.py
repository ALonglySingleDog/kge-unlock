#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations



def print_report(info):
    tags = info['tags']
    print('解密成功')
    print('密钥 A (272 字节): ' + info['key_a'])
    print('密钥 B (16 字节): ' + info['key_b'])
    print('KGE 加密类型: ' + str(info['kind']))
    print('文件格式: ' + {'vorbis': 'OGG (Vorbis)', 'opus': 'OGG (Opus)', 'ogg': 'OGG', 'mp3': 'MP3', 'flac': 'FLAC'}.get(info['codec'], info['codec'].upper()))
    print('音质: ' + info['quality'])
    print('歌曲名: ' + (tags.get('TITLE') or '未知'))
    print('歌手: ' + (tags.get('ARTIST') or '未知'))
    print('专辑: ' + (tags.get('ALBUM') or '未知'))
    print('输出文件名: ' + info['output'].name)
    print('输出路径: ' + str(info['output']))
