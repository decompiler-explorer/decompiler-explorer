import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REVNG_INSTALL = Path(os.getenv("REVNG_INSTALL_PATH", "/revng"))
REVNG_CLI = REVNG_INSTALL / 'revng'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()

        ptml_path = Path(tempdir) / 'output.ptml'
        decomp = subprocess.run([REVNG_CLI, "artifact", "decompile-to-single-file", "--analyze", infile.name, "-o", str(ptml_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tempdir)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)

        infile.close()

        c_path = Path(tempdir) / 'output.c'
        parse = subprocess.run([REVNG_CLI, "ptml", "-p", "-o", str(c_path), str(ptml_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=tempdir)
        if parse.returncode != 0:
            print(f'{parse.stdout.decode()}\n{parse.stderr.decode()}')
            sys.exit(1)

        with open(c_path, "rb") as f:
            sys.stdout.buffer.write(f.read())


def version():
    proc = subprocess.run([REVNG_CLI, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # rev.ng version @VERSION@
    output = proc.stdout.decode()
    assert output.startswith('rev.ng version ')
    version = ' '.join(output.split(' ')[2:])

    print(version)
    print()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('rev.ng')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://rev.ng/')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
