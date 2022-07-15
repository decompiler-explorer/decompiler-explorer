import sys
import time
import traceback
from typing import List

import angr
from angr.analyses import CFGFast, Decompiler
from angr.knowledge_plugins import Function
from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

decompiler_metadata = {
    "name": "angr",
    "version": angr.__version__,
    "url": "https://angr.io",
}


@app.route("/metadata")
def metadata():
    return make_response(jsonify(decompiler_metadata))


@app.route("/decompile")
def decompile():
    path = request.args.get("path")

    start = time.time()

    p = angr.Project(path, auto_load_libs=False, load_debug_info=False)
    cfg: CFGFast = p.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
    )
    p.analyses.CompleteCallingConventions(
        cfg=cfg, recover_variables=True, analyze_callsites=True
    )

    funcs_to_decompile: List[Function] = [
        func
        for func in cfg.functions.values()
        if not func.is_plt and not func.is_simprocedure and not func.alignment
    ]

    output = ""
    for func in funcs_to_decompile:
        try:
            decompiler: Decompiler = p.analyses.Decompiler(func)

            if decompiler.codegen:
                output += decompiler.codegen.text
                output += "\n"
            if decompiler.codegen is None:
                output += f"// No decompilation output for function {func.name}\n"
        except Exception as e:
            output += "// An error occurred while decompiling function {func.name}\n"
            print(f"Exception thrown decompiling function {func.name}:")
            print(traceback.format_exc())

    end = time.time()

    return make_response(
        jsonify(
            {
                "decompiler_metedata": decompiler_metadata,
                "output": output,
                "time": end - start,
            }
        )
    )


if __name__ == "__main__":
    client = app.test_client()
    print(client.get("/decompile?path=" + sys.argv[1]).json["output"])
