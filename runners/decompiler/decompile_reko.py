import os
import subprocess
import sys
import tempfile
from pathlib import Path


REKO_INSTALL = Path(os.getenv("REKO_INSTALL_PATH", "/home/decompiler_user/reko"))
REKO_DECOMPILE = REKO_INSTALL / 'reko'


def main():
    cwd = Path.cwd()
    conts = sys.stdin.buffer.read()
    infile = tempfile.NamedTemporaryFile(dir=cwd, delete=False)
    infile.write(conts)
    infile.flush()

    # Keep Reko diagnostics out of stdout (which is reserved for decompiled C).
    # The parent runner bounds stderr and kills this entire process group on overflow.
    decomp = subprocess.run([REKO_DECOMPILE, infile.name], stdout=sys.stderr,
                            stderr=sys.stderr, cwd=cwd)
    if decomp.returncode != 0:
        raise SystemExit(f"Reko exited with status {decomp.returncode}")
    infile.close()

    outputs = Path(infile.name + ".reko")
    seen = set()
    for source in outputs.glob('*text*.c'):
        with open(source, 'rb') as f:
            seen.add(source)
            for block in iter(lambda: f.read(65536), b''):
                sys.stdout.buffer.write(block)
    for source in outputs.glob('*.c'):
        if source in seen:
            continue
        with open(source, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sys.stdout.buffer.write(block)


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
