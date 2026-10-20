#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from kge_crypto import KgeError, TEMPLATE
from native_transforms import transform
from ogg_recover import recover_ogg
from padding_recover import recover_padding
from statistical_recover import recover_statistical

def recover_automatic_key(src: Path):
    problems = []
    for title, getter in (
        ('Ogg CRC', recover_ogg),
        ('zero padding', recover_padding),
        ('byte statistics', recover_statistical),
    ):
        try:
            h, key = getter(src)
            if transform(h.kind, TEMPLATE, key.a272, key.b16, encrypt=True) != h.wrapped_template:
                raise KgeError('Recovered key does not match encrypted KGE header')
            return h, key, title
        except KgeError as exc:
            problems.append('%s: %s' % (title, exc))
    raise KgeError('Unable to recover native key; ' + ' | '.join(problems))
