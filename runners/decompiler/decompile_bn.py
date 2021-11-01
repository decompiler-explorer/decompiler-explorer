import html
import os
import sys
import tempfile

import binaryninja
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType


def add_output(s):
    sys.stdout.write(s)

def print_decompilation():
    t = tempfile.NamedTemporaryFile()
    t.write(sys.stdin.buffer.read())
    t.flush()

    bv = binaryninja.open_view(t.name, update_analysis=True)
    if bv is None:
        raise Exception("Unable to open view for binary")

    add_output('''<link href="https://fonts.googleapis.com/css?family=Source+Code+Pro" rel="stylesheet"><style>
body { margin: 0; background-color: rgb(43, 43, 43); font-family: 'Source Code Pro', monospace;  white-space: pre; padding: 0; font-size: 12px; }
.headerline { background-color: rgb(93, 93, 93); }
.KeywordToken { color: rgb(237, 223, 179); }
.RegisterToken { color: rgb(237, 223, 179); }
.DataSymbolToken { color: rgb(142, 230, 237); }
.TextToken { color: rgb(224, 224, 224); }
.InstructionToken { color: rgb(224, 224, 224); }
.BeginMemoryOperandToken { color: rgb(224, 224, 224); }
.EndMemoryOperandToken { color: rgb(224, 224, 224); }
.OperandSeparatorToken { color: rgb(224, 224, 224); }
.PossibleAddressToken { color: rgb(162, 217, 175); }
.IntegerToken { color: rgb(162, 217, 175); }
.AddressDisplayToken { color: rgb(162, 217, 175); }
.AnnotationToken { color: rgb(218, 196, 209); }
.ImportToken { color: rgb(237, 189, 129); }
.CodeRelativeAddressToken { color: rgb(162, 217, 175); }
.StackVariableToken { color: rgb(193, 220, 199); }
.LocalVariableToken { color: rgb(128, 198, 233); }
.ArgumentNameToken { color: rgb(128, 198, 233); }
.FieldNameToken { color: rgb(176, 221, 228); }
.TypeNameToken { color: rgb(237, 189, 129); }
.StringToken { color: rgb(218, 196, 209); }
.CodeSymbolToken { color: rgb(128, 198, 233); }
.OpcodeToken { color: rgb(144, 144, 144); }
.HexDumpByteValueToken { color: rgb(224, 224, 224); }
.CharacterConstantToken { color: rgb(218, 196, 209); }
.GoToLabelToken { color: rgb(128, 198, 233); }
.StructOffsetToken { color: rgb(176, 221, 228); }
.ImportToken, .IndirectImportToken { color: rgb(237, 189, 129); }

.code { display: inline-block; min-width: calc(100% - 24px); }
.line { padding: 0 12px 0 12px; width: 100%; color: rgb(224, 224, 224); }
.headerline {
    padding-top: 8px;
    margin-top: 8px;
    border-top: 1px solid #fff;
    padding-bottom: 8px;
    margin-bottom: 8px;
    border-bottom: 1px solid #fff;
}

.hr { padding: 0px 12px 0px 12px; border: 0; border-top: 1px solid #fff; margin: 10px 0 10px 0; width: 100%; height: 1px; }
.endline {
    background-color: #000;
}
</style><div class="code">''')

    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
    settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
    settings.set_option(DisassemblyOption.WaitForIL)

    for func in bv.functions:
        obj = lineardisassembly.LinearViewObject.single_function_language_representation(func, settings)
        cursor = obj.cursor
        while True:
            for line in cursor.lines:
                if line.type == LinearDisassemblyLineType.LocalVariableListEndLineType:
                    add_output('<div class="hr"></div>')
                    continue
                elif line.type == LinearDisassemblyLineType.FunctionEndLineType:
                    add_output('<div class="hr"></div>')
                elif line.type == LinearDisassemblyLineType.FunctionHeaderLineType:
                    # TODO: this makes split function header lines look wrong
                    add_output('<div class="line headerline">')
                else:
                    add_output('<div class="line">')

                for i in line.contents.tokens:
                    add_output('<span class="' + i.type.name + '">')
                    add_output(html.escape(str(i)))
                    add_output('</span>')

                add_output('</div>')

            if not cursor.next():
                break

    add_output('</div>')


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

    print_decompilation()


