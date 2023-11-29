import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REKO_INSTALL = Path(os.getenv("REKO_INSTALL_PATH", "/home/decompiler_user/reko"))
REKO_DECOMPILE = REKO_INSTALL / 'reko'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()

        decomp = subprocess.run([REKO_DECOMPILE, infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)
        infile.close()

        outputs = Path(infile.name + ".reko")
        seen = set()
        for source in outputs.glob('*text*.c'):
            with open(source, 'rb') as f:
                seen.add(source)
                sys.stdout.buffer.write(f.read())
        for source in outputs.glob('*.c'):
            if source in seen:
                continue
            with open(source, 'rb') as f:
                sys.stdout.buffer.write(f.read())


def version():
    proc = subprocess.run([REKO_DECOMPILE, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Reko decompiler version 0.11.5.0 (git:36c3481)
    output = proc.stdout.decode().strip()
    assert 'Reko decompiler version ' in output
    version = output.split(' ')[3]

    revision = output.split(' ')[4]
    assert '(git:' in revision
    revision = revision[5:-1]

    print(version)
    print(revision)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Reko')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://github.com/uxmal/reko')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
