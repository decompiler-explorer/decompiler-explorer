from __future__ import print_function

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import idautils
import os.path

# becsause the -S script runs very early, we need to load the decompiler
# manually if we want to use it
def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False


def main():
    idbpath = idc.get_idb_path()
    cpath = os.path.join(os.path.dirname(idbpath), "version.txt")
    with open(cpath, "w") as outfile:
        if init_hexrays():
            outfile.write(ida_hexrays.get_hexrays_version())
        else:
            outfile.write(str(ida_ida.inf_get_version() / 100))
    ida_pro.qexit(0)


main()