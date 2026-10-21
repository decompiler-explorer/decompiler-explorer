import subprocess
import sys
import tempfile
from pathlib import Path


OBJDUMP = "objdump"


def print_metadata(option):
    if option == "--name":
        print("objdump")
        return True
    if option == "--url":
        print("https://www.gnu.org/software/binutils/")
        return True
    if option == "--version":
        version = subprocess.check_output([OBJDUMP, "--version"], text=True).splitlines()[0]
        print(version)
        print("")  # No separate revision information.
        return True
    return False


def disassemble():
    contents = sys.stdin.buffer.read()
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as tempdir:
        binary = Path(tempdir) / "input.bin"
        binary.write_bytes(contents)

        proc = subprocess.run(
            [OBJDUMP, "--disassemble", "--demangle", "--wide", binary.name],
            cwd=tempdir,
        )

    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


if __name__ == "__main__":
    if len(sys.argv) > 1 and print_metadata(sys.argv[1]):
        raise SystemExit(0)
    disassemble()
