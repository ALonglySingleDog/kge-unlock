#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
import traceback
from pathlib import Path
from decryptor import decrypt_one
from reporting import print_report

def main() -> int:
    try:
        result = decrypt_one(Path(sys.argv[1]))
    except Exception:
        print('解密失败，错误日志：', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1
    print_report(result)
    return 0


if __name__ == '__main__':
    sys.exit(main())
