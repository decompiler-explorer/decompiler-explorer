import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REKO_INSTALL = Path(os.getenv("REKO_INSTALL_PATH", "/home/decompiler_user/reko"))
REKO_DECOMPILE = REKO_INSTALL / 'decompile'


def main():
    tempdir = tempfile.TemporaryDirectory()

    conts = sys.stdin.buffer.read()
    infile = tempfile.NamedTemporaryFile(dir=tempdir.name, delete=False)
    infile.write(conts)
    infile.flush()

    decomp = subprocess.run([REKO_DECOMPILE, infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    infile.close()

    sys.stdout.buffer.write(b'<pre>')
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

    sys.stdout.buffer.write(b'</pre>')

    shutil.rmtree(tempdir.name)


def version():
    proc = subprocess.run([REKO_DECOMPILE, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Decompile.exe version 0.11.2.0 (git:42a17f5d0)
    output = proc.stdout.decode().strip()
    assert 'Decompile.exe version ' in output
    version = output.split(' ')[2]

    revision = output.split(' ')[3]
    assert '(git:' in revision
    revision = revision[5:-1]

    print(version)
    print(revision)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Reko')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
