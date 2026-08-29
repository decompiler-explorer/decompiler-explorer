import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


KUNA_INSTALL = Path(os.getenv("KUNA_INSTALL_PATH", "/kuna"))
KUNA_BIN = KUNA_INSTALL / 'kuna'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()

        decomp = subprocess.run([KUNA_BIN, 'decompile-all', infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=KUNA_INSTALL)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            return
        infile.close()

        sys.stdout.buffer.write(decomp.stdout)


def version():
    proc = subprocess.run([KUNA_BIN, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # kuna 0.1.0
    output = proc.stdout.decode().strip()
    revision = ''
    version = output[5:]

    print(version)
    print(revision)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Kuna')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://github.com/Noelo-Lab/kuna')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
