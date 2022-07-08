import html
import os
import sys
import tempfile

import binaryninja
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType


def main():
    t = tempfile.NamedTemporaryFile()
    t.write(sys.stdin.buffer.read())
    t.flush()

    bv = binaryninja.open_view(t.name, update_analysis=True)
    if bv is None:
        raise Exception("Unable to open view for binary")

    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
    settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
    settings.set_option(DisassemblyOption.WaitForIL)

    for func in bv.functions:
        obj = lineardisassembly.LinearViewObject.single_function_language_representation(func, settings)
        cursor = obj.cursor
        while True:
            for line in cursor.lines:
                if line.type in [
                    LinearDisassemblyLineType.FunctionHeaderStartLineType,
                    LinearDisassemblyLineType.FunctionHeaderEndLineType,
                    LinearDisassemblyLineType.AnalysisWarningLineType,
                ]:
                    continue
                for i in line.contents.tokens:
                    if i.type == InstructionTextTokenType.TagToken:
                        continue
                    sys.stdout.write(str(i))
                print("")

            if not cursor.next():
                break


if __name__ == "__main__":
    os.environ['BN_DISABLE_USER_SETTINGS'] = '1'
    os.environ['BN_DISABLE_USER_PLUGINS'] = '1'
    os.environ['BN_DISABLE_REPOSITORY_PLUGINS'] = '1'

    if len(sys.argv) > 1 and sys.argv[1] == '--version':
        version = binaryninja.core_version()
        if '-' in version:
            version = version.split('-')[0]
        print(version)
        print(f'{binaryninja.core_build_id():x}')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--name':
        print('BinaryNinja')
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--url':
        print('https://binary.ninja/')
        sys.exit(0)

    main()


