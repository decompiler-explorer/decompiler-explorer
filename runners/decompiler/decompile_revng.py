import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


REVNG_INSTALL = Path(os.getenv("REVNG_INSTALL_PATH", "/revng"))
REVNG_CLI = REVNG_INSTALL / 'revng'


def main():
    cwd = Path.cwd()
    conts = sys.stdin.buffer.read()
    infile = tempfile.NamedTemporaryFile(dir=cwd, delete=False)
    infile.write(conts)
    infile.flush()

    ptml_path = cwd / 'output.ptml'
    decomp = subprocess.run([REVNG_CLI, "quick", "artifact", "emit-c-as-single-file", infile.name, "-o", str(ptml_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    if decomp.returncode != 0:
        print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
        return

    infile.close()

    c_path = cwd / 'output.c'
    parse = subprocess.run([REVNG_CLI, "ptml", "--plain", str(ptml_path), "-o", str(c_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    if parse.returncode != 0:
        print(f'{parse.stdout.decode()}\n{parse.stderr.decode()}')
        return

    with open(c_path, "rb") as f:
        sys.stdout.buffer.write(f.read())


def version():
    # They deleted --version a couple releases ago so now we have to source
    # their bash environment to spawn a python to read the variable (why)
    proc = subprocess.run([
        '/bin/bash',
        '-c',
        textwrap.dedent(f"""
        source {REVNG_INSTALL / "environment"} &&
        python3 -c 'import revng; print(revng.__version__)'
        """)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # rev.ng version @VERSION@
    output = proc.stdout.decode()
    version = output.strip()

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
