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


# Angr
FROM base-x86 as angr
RUN pip install --user 'angr>=9.1,<10.0'
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

RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip -O ghidra.zip \
    && unzip ghidra.zip \
    && rm ghidra.zip

COPY DecompilerExplorer.java .
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
