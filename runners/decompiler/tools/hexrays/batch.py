#! /usr/bin/python3
# -*- coding: utf-8 -*-
#
#       Batch decompile the specified files using the Hex-Rays Decompiler.
#       This script requires efd64, an utility that determines if the input
#       file is decompilable by the Hex-Rays Decompiler.
#
#       Library functions are skipped during decompilation.
#
#       Copyright (c) 2022 Hex-Rays SA
#

import os
import sys
import shutil
import argparse
import subprocess

# supported hexrays platforms
HEX_NONE   = 0x000 # invalid
HEX_X86    = 0x001 # hexx86
HEX_X64    = 0x002 # hexx64
HEX_ARM    = 0x004 # hexarm
HEX_ARM64  = 0x008 # hexarm64
HEX_PPC    = 0x010 # powerpc
HEX_PPC64  = 0x020 # powerpc64
HEX_MIPS   = 0x040 # mips
HEX_MIPS64 = 0x080 # mips64

platforms_32 = [HEX_X86, HEX_ARM,   HEX_PPC,   HEX_MIPS  ]
platforms_64 = [HEX_X64, HEX_ARM64, HEX_PPC64, HEX_MIPS64]

#----------------------------------------------------------------------------
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)


#----------------------------------------------------------------------------
# delete all files starting with 'path' and having the 'exts' extensions
def delete_files(path, exts):
  for ext in exts:
    tmpfile = path + ext
    if os.path.exists(tmpfile):
      os.unlink(tmpfile)

#----------------------------------------------------------------------------
# determine the bitness of the specificed file.
# returns: 32 or 64. if the file is not decompilable, returns 0.
# this function uses an utility called 'efd64'
def get_bitness(efd, path):
  # check if the input file is decompilable, and its bitness
  p = subprocess.run([efd, '-z', path])
  exit_code = p.returncode
  if exit_code >= 64 and exit_code != 255:
    exit_code -= 64
    for plfm in platforms_64:
      if exit_code & plfm:
        return 64
    for plfm in platforms_32:
      if exit_code & plfm:
        return 32
  return 0

#----------------------------------------------------------------------------
def main():
  # parse command line arguments
  parser = argparse.ArgumentParser(description='Batch decompile a file')
  parser.add_argument('--idadir', '-d', type=str,
                      help='Directory with IDA Pro executable')
  parser.add_argument('--timeout', '-T', type=int,
                      help='Timeout in seconds')
  parser.add_argument('--keep-idb', '-k', action='store_true',
                      help='Do not delete the database after decompilation')
  parser.add_argument('input_files', nargs='+', default=[],
                      help='Input files to decompile')
  args = parser.parse_args(sys.argv[1:])

  # determine IDA installation directory
  idadir = args.idadir
  if not idadir:
    idat = shutil.which('idat64')
    if idat:
      idadir = os.path.dirname(idat)
    else:
      eprint('failed to find idat64, please use -d to specify the path to it')
      sys.exit(1)
  while not os.path.isdir(idadir):
    idadir = os.path.dirname(idadir)
    if len(idadir) == 0:
      eprint('wrong IDA directory', args.idadir)
      sys.exit(1)

  # check if efd64 is available
  efd = os.path.join(idadir, 'efd64')
  if not os.path.isfile(efd):
    eprint('%s: is required for batch decompilation but is missing' % efd)
    sys.exit(1)

  # decompile all specified files
  for input in args.input_files:
    if not os.path.isfile(input):
      eprint('%s: is no such file' % input)
      continue
    bitness = get_bitness(efd, input)
    if bitness == 0:
      eprint('%s: is not decompilable' % input)
      continue

    # we just ask ida to batch decompile using the option -Ohexrays
    is64 = bitness == 64
    idat = os.path.join(idadir, 'idat64' if is64 else 'idat')
    hexopt = '-Ohexrays:-errs:' + input + '.c:ALL'
    try:
      p = subprocess.run([idat, hexopt, '-c', '-A', input], timeout=args.timeout)
    except subprocess.TimeoutExpired:
      # clean up temporary files
      if not args.keep_idb:
        delete_files(input, ['.id0', '.id1', '.id2', '.nam', '.til'])
      eprint('%s: decompilation timed out' % input)

    # delete the database unless asked otherwise
    if not args.keep_idb:
      delete_files(input, ['.i64' if is64 else '.idb'])

#----------------------------------------------------------------------------
main()
