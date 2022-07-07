# Private Installers
To build some decompiler images, you need to provide binaries and licenses that are not publicly available. Here is a list of all the various files required:

## Binary Ninja:
From a Linux installation, you have to copy the binaries and license information:

Copy the binaries:
- `cp -r ~/binaryninja runners/decompiler/tools/binja/`

Copy the license:
- `cp ~/.binaryninja/license.dat runners/decompiler/tools/binja/`

## Hex-Rays:
From a Linux installation, you must first run IDA and accept the terms of service. Then, you can copy the following:

Copy the binaries:
- `cp -r /opt/idapro-7.7 runners/decompiler/tools/hexrays/ida`

Copy the registry:
- `cp -r ~/.idapro runners/decompiler/tools/hexrays`

Copy efd64 for batch processing:
- `cp efd64 runners/decompiler/tools/hexrays`
