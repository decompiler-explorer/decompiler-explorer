import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GHIDRA_INSTALL = Path(os.getenv("GHIDRA_INSTALL_PATH", "/home/decompiler_user/ghidra"))
GHIDRA_HEADLESS = GHIDRA_INSTALL / 'support' / 'analyzeHeadless'

GHIDRA_APP_PROPERTIES = GHIDRA_INSTALL / 'Ghidra' / 'application.properties'

def main():
    with tempfile.TemporaryDirectory() as tempdir:
        conts = sys.stdin.buffer.read()
        infile = tempfile.NamedTemporaryFile(dir=tempdir, delete=False)
        infile.write(conts)
        infile.flush()
        inname = infile.name
        infile.close()

        project_dir = tempfile.TemporaryDirectory(dir=tempdir)
        output_dir = tempfile.TemporaryDirectory(dir=tempdir)

        output_file = output_dir.name + "/out"
        parent_dir = Path(__file__).resolve().parent

        decompile_command = [
            f"{GHIDRA_HEADLESS}",
            project_dir.name,
            "temp",
            "-import",
            inname,
            "-scriptPath",
            f"{parent_dir}",
            "-postScript",
            f"{parent_dir}/DecompilerExplorer.java",
            output_file
        ]

        if not os.path.exists(output_file):
            decomp = subprocess.run(decompile_command, capture_output=True)
            if decomp.returncode != 0 or not os.path.exists(output_file):
                print(f'{decomp.stdout.decode()}\n{decomp.stderr.decode()}')
                sys.exit(1)

        with open(output_file, 'r') as f:
            print(f.read())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version = None
        revision = None
        for line in GHIDRA_APP_PROPERTIES.read_text().splitlines():
            name, val = line.split('=')
            if name == 'application.version':
                version = val
                break
        for line in GHIDRA_APP_PROPERTIES.read_text().splitlines():
            name, val = line.split('=')
            if name == 'application.revision.ghidra':
                revision = val
                break
        if version is not None and revision is not None:
            print(version)
            print(revision)
        else:
            print("Unknown")
            print("Unknown")
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('Ghidra')
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://ghidra-sre.org')
        sys.exit(0)

    main()
