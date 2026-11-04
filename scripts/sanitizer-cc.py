#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test-only compiler wrapper; callers use --standalone for every Goose build."""
import os
import shutil
import sys

compiler = shutil.which(os.environ.get('URL_SANITIZER_CC', 'gcc'))
if compiler is None:
    raise SystemExit('sanitizer compiler not found')
args = sys.argv[1:]
probe = bool(args) and all(arg in ['-v', '--version', '-dumpversion', '-dumpfullversion', '-dumpmachine'] for arg in args)
flags = [] if probe else ['-O1', '-g', '-fno-omit-frame-pointer',
                          '-fsanitize=address,undefined', '-fno-sanitize-recover=all']
if not probe and not any(arg in args for arg in ['-c', '-E', '-S']):
    flags.append('-no-pie')
os.execv(compiler, [compiler, *args, *flags])
