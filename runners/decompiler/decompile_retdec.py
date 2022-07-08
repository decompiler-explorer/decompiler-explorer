import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


RETDEC_INSTALL = Path(os.getenv("RETDEC_INSTALL_PATH", "/home/decompiler_user/retdec/bin"))
RETDEC_DECOMPILER = RETDEC_INSTALL / 'retdec-decompiler'


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()
        outfile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        outfile.close()

        decomp = subprocess.run([RETDEC_DECOMPILER, '--output', outfile.name, '--cleanup', '--silent', infile.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if decomp.returncode != 0:
            print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
            sys.exit(1)
        infile.close()

        with open(outfile.name, 'rb') as f:
            sys.stdout.buffer.write(f.read())


def version():
    proc = subprocess.run([RETDEC_DECOMPILER, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # RetDec version :  v4.0-415-g05c9b113
    # Commit hash    :  05c9b11351d3e82012d823fa3709f940033768cf
    # Build date     :  2022-04-13T20:37:02Z
    output = proc.stdout.decode()
    lines = output.split('\n')
    version_lines = [l for l in lines if l.startswith('RetDec version : ')]
    assert len(version_lines) == 1
    revision = version_lines[0][-9:]
    version = version_lines[0][19:-10]

    print(version)
    print(revision)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('RetDec')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://github.com/avast/retdec')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version()
        sys.exit(0)

    main()
