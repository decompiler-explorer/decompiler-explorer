import sys
import tempfile
import angr

from angr.analyses import CFGFast, Decompiler
from angr.analyses.decompiler import StructuredCodeGenerator
from angr.knowledge_plugins import Function


def decompile():
    conts = sys.stdin.buffer.read()
    t = tempfile.NamedTemporaryFile()
    t.write(conts)
    t.flush()

    p = angr.Project(t.name)
    cfg: CFGFast = p.analyses.CFGFast()

    for start in cfg.kb.functions:
        try:
            fn: Function = cfg.functions[start]
            fn.normalize()
            decompiler: Decompiler = p.analyses.Decompiler(fn)

            if decompiler.kb.structured_code.available_flavors(start):
                codegen: StructuredCodeGenerator = decompiler.codegen

                if codegen:
                    codegen.regenerate_text()
                    print(f"{codegen.text}")
        except Exception as e:
            print(f"Exception thrown decompiling function at 0x{start:x}: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        print('.'.join(str(i) for i in angr.__version__))
        print('')  # No revision information known
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('angr')
        sys.exit(0)

    decompile()
