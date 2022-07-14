FROM python:3.8-slim-bullseye as base

RUN useradd -ms /bin/false decompiler_user
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN pip install --user 'requests>=2.27,<3.0'

FROM --platform=amd64 python:3.8-slim-bullseye as base-x86

RUN useradd -ms /bin/false decompiler_user
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN pip install --user 'requests>=2.27,<3.0'


# Binary Ninja
FROM base-x86 as binja
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*
USER decompiler_user

RUN mkdir ~/.binaryninja
COPY tools/binja/license.dat /home/decompiler_user/.binaryninja/license.dat
COPY tools/binja/binaryninja /home/decompiler_user/binaryninja/
COPY decompile_bn.py .
ENV PYTHONPATH=/home/decompiler_user/binaryninja/python/:$PYTHONPATH

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_bn.py" ]


# angr
FROM base-x86 as angr
RUN pip install --user 'angr>=9.2.10,<10.0'
COPY decompile_angr.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_angr.py" ]


# Ghidra
FROM base as ghidra
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-11-jdk unzip wget \
    && rm -rf /var/lib/apt/lists/*
USER decompiler_user

RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip -O ghidra.zip \
    && unzip ghidra.zip \
    && rm ghidra.zip \
    && mv ghidra_* ghidra

COPY tools/ghidra/DecompilerExplorer.java .
COPY decompile_ghidra.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_ghidra.py" ]

# Snowman
FROM base-x86 as snowman
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git libboost-dev qtbase5-dev qt5-qmake qtbase5-dev-tools \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN git clone https://github.com/yegord/snowman.git \
    && cmake -B snowman/build -DNC_QT5=YES -DCMAKE_INSTALL_PREFIX=install snowman/src/ \
    && cmake --build snowman/build -j$(nproc) \
    && cmake --install snowman/build \
    && rm -rf snowman

COPY decompile_snowman.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_snowman.py" ]

# RetDec
FROM base-x86 as retdec
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget xz-utils \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN wget https://retdec-tc.avast.com/repository/download/RetDec_LinuxBuild/.lastSuccessful/package/retdec-master-linux-64b.tar.xz?guest=1 \
    && tar xf 'retdec-master-linux-64b.tar.xz?guest=1' \
    && rm 'retdec-master-linux-64b.tar.xz?guest=1'
COPY decompile_retdec.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_retdec.py" ]

# RecStudio
FROM base-x86 as recstudio
USER root
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends wget libc6:i386 libstdc++6:i386 \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN wget http://www.backerstreet.com/rec/RecStudioLinux.tgz \
    && tar xf 'RecStudioLinux.tgz' \
    && rm 'RecStudioLinux.tgz' \
    && mkdir output
WORKDIR /home/decompiler_user
COPY decompile_recstudio.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_recstudio.py" ]

# Reko
FROM base-x86 as reko
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git build-essential cmake wget gcc g++ libcapstone-dev pkg-config p7zip-full unzip \
    && wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y apt-transport-https \
    && apt-get update \
    && apt-get install -y dotnet-sdk-5.0 \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN git clone https://github.com/uxmal/reko.git \
    && cd reko \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=UnixRelease -t:build_solution -m ./src/BuildTargets/BuildTargets.csproj \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_runtime_nupkg -m ./src/BuildTargets/BuildTargets.csproj \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_release -m ./src/BuildTargets/BuildTargets.csproj \
    && cp bin/CmdLine*.zip ../CmdLine.zip \
    && cd .. \
    && rm -rf reko

RUN mkdir reko \
    && cd reko \
    && unzip ../CmdLine.zip

WORKDIR /home/decompiler_user
COPY decompile_reko.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_reko.py" ]

# Boomerang
FROM base-x86 as boomerang
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget bzip2 libexpat1 qtbase5-dev libcapstone-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/BoomerangDecompiler/boomerang/releases/download/v0.5.2/boomerang-v0.5.2-linux64.tar.gz -O boomerang.tar.gz \
    && tar xf boomerang.tar.gz \
    && rm boomerang.tar.gz \
    && cp -r boomerang*/* /usr \
    && ln -s /usr/lib/boomerang/libboomerang.so /usr/lib

USER decompiler_user
WORKDIR /home/decompiler_user
COPY decompile_boomerang.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_boomerang.py" ]

# Hex-Rays
FROM base-x86 as hexrays

COPY tools/hexrays/.idapro /home/decompiler_user/.idapro/
COPY tools/hexrays/ida /home/decompiler_user/ida/
COPY tools/hexrays/efd64 /home/decompiler_user/ida
COPY tools/hexrays/batch.py /home/decompiler_user/ida
COPY tools/hexrays/version.py /home/decompiler_user/ida

USER root
RUN /home/decompiler_user/ida/idapyswitch --force-path /usr/local/lib/libpython3.8.so \
    && chmod +x /home/decompiler_user/ida/efd64 \
    && chown -R decompiler_user /home/decompiler_user/ida \
    && chown -R decompiler_user /home/decompiler_user/.idapro

USER decompiler_user
WORKDIR /home/decompiler_user

COPY decompile_hexrays.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_hexrays.py" ]
