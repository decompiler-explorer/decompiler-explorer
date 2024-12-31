FROM python:3.10-slim-bookworm AS base

RUN useradd -ms /bin/false decompiler_user
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN pip install --user 'requests>=2.27,<3.0'

FROM --platform=amd64 python:3.10-slim-bookworm AS base-x86

RUN useradd -ms /bin/false decompiler_user
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN pip install --user 'requests>=2.27,<3.0'


# Binary Ninja
FROM base-x86 AS binja
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
FROM base-x86 AS angr
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
RUN pip install --user 'angr~=9.2.135'
COPY decompile_angr.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_angr.py" ]


# Ghidra
FROM base AS ghidra
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip wget libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://aka.ms/download-jdk/microsoft-jdk-21.0.4-linux-$(uname -m | sed 's/x86_64/x64/').tar.gz \
    && tar xf microsoft-jdk-21.0.4-linux-$(uname -m | sed 's/x86_64/x64/').tar.gz \
    && rm microsoft-jdk-21.0.4-linux-$(uname -m | sed 's/x86_64/x64/').tar.gz \
    && mv jdk-21.0.4+7 jdk

USER decompiler_user

RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip -O ghidra.zip \
    && unzip ghidra.zip \
    && rm ghidra.zip \
    && mv ghidra_* ghidra

COPY tools/ghidra/DecompilerExplorer.java .
COPY decompile_ghidra.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_ghidra.py" ]

# Snowman
FROM base-x86 AS snowman
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git libboost-dev qtbase5-dev qt5-qmake qtbase5-dev-tools \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN git clone https://github.com/mborgerson/snowman.git \
    && cmake -B snowman/build -DNC_QT5=YES -DCMAKE_INSTALL_PREFIX=install snowman/src/ \
    && cmake --build snowman/build -j$(nproc) \
    && cmake --install snowman/build \
    && rm -rf snowman

COPY decompile_snowman.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_snowman.py" ]

# RetDec
FROM base-x86 AS retdec
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget xz-utils \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN wget https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz \
    && mkdir retdec \
    && cd retdec \
    && tar xf ../RetDec-v5.0-Linux-Release.tar.xz \
    && cd .. \
    && rm RetDec-v5.0-Linux-Release.tar.xz
COPY decompile_retdec.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_retdec.py" ]

# RecStudio
FROM base-x86 AS recstudio
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
FROM base-x86 AS reko
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git build-essential cmake wget gcc g++ libcapstone-dev pkg-config p7zip-full unzip \
    && wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y apt-transport-https \
    && apt-get update \
    && apt-get install -y dotnet-sdk-6.0 \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user
RUN git clone --depth=1 https://github.com/uxmal/reko.git \
    && cd reko \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=UnixRelease -t:build_solution -m ./src/BuildTargets/BuildTargets.csproj \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_runtime_nupkg -m ./src/BuildTargets/BuildTargets.csproj \
    && dotnet msbuild -p:Platform=x64 -p:Configuration=Release -t:create_release -m ./src/BuildTargets/BuildTargets.csproj \
    && cp bin/CmdLine*.zip ../CmdLine.zip \
    && cd .. \
    && rm -rf reko .nuget

RUN mkdir reko \
    && cd reko \
    && unzip ../CmdLine.zip

WORKDIR /home/decompiler_user
COPY decompile_reko.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_reko.py" ]

# Boomerang
FROM base-x86 AS boomerang
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
FROM base-x86 AS hexrays

COPY tools/hexrays/.idapro /home/decompiler_user/.idapro/
COPY tools/hexrays/ida /home/decompiler_user/ida/
COPY tools/hexrays/efd64 /home/decompiler_user/ida
COPY tools/hexrays/batch.py /home/decompiler_user/ida
COPY tools/hexrays/version.py /home/decompiler_user/ida

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsecret-1-0 \
    && rm -rf /var/lib/apt/lists/*

RUN /home/decompiler_user/ida/idapyswitch --force-path /usr/local/lib/libpython3.10.so \
    && chmod +x /home/decompiler_user/ida/efd64 \
    && chown -R decompiler_user /home/decompiler_user/ida \
    && chown -R decompiler_user /home/decompiler_user/.idapro

USER decompiler_user
WORKDIR /home/decompiler_user

COPY decompile_hexrays.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_hexrays.py" ]

# Dewolf
FROM base-x86 AS dewolf
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-3 \
    && apt-get install -y --no-install-recommends astyle libgraph-easy-perl git \
    && pip install pipenv \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN mkdir ~/.binaryninja
COPY tools/dewolf/license.dat /home/decompiler_user/.binaryninja/license.dat
COPY tools/dewolf/binaryninja /home/decompiler_user/binaryninja/

RUN git clone --depth=1 --branch=v2024-10-01 https://github.com/fkie-cad/dewolf.git \
    && cd dewolf \
    && pipenv install -r ./requirements.txt \
    && pipenv run python /home/decompiler_user/binaryninja/scripts/install_api.py

ENV PYTHONPATH=/home/decompiler_user/binaryninja/python/:$PYTHONPATH
COPY decompile_dewolf.py .
COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_dewolf.py" ]

# Relyze
FROM base-x86 AS relyze
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget
RUN mkdir -pm755 /etc/apt/keyrings \
    && wget -nc --no-check-certificate -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -nc --no-check-certificate -P /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends winehq-stable \
    && rm -rf /var/lib/apt/lists/*
RUN wget -nc -O /innoextract_amd64.deb https://download.opensuse.org/repositories/home:/dscharrer/Debian_11/amd64/innoextract_1.9-0.1_amd64.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends /innoextract_amd64.deb \
    && rm /innoextract_amd64.deb \
    && rm -rf /var/lib/apt/lists/*

USER decompiler_user
WORKDIR /home/decompiler_user

RUN wget -O ./update_win64.xml https://www.relyze.com/update?family=RLZ\&plat=win\&arch=x64 \
    && wget -O ./Relyze_Desktop_x_x_x_win64.exe https://www.relyze.com/$(grep -oP "(?<=<Installer>)(\S+)(?=</Installer>)" update_win64.xml) \
    && rm ./update_win64.xml
RUN innoextract  -d ./RelyzeDesktop ./Relyze_Desktop_x_x_x_win64.exe \
    && rm ./Relyze_Desktop_x_x_x_win64.exe
ENV WINEPREFIX=/home/decompiler_user/.wine-relyze
RUN winecfg 2>/dev/null && wineserver --kill
ENV WINEDLLOVERRIDES="dbghelp=n;symsrv=n"
RUN rm -rf $WINEPREFIX/drive_c/users/decompiler_user/Documents
RUN mkdir $WINEPREFIX/drive_c/users/decompiler_user/Documents
RUN ln -s /home/decompiler_user/RelyzeDesktop/commonappdata/Relyze64 $WINEPREFIX/drive_c/ProgramData/Relyze64
RUN mkdir -p $WINEPREFIX/drive_c/users/decompiler_user/AppData/Roaming/Relyze

COPY tools/relyze/License.txt $WINEPREFIX/drive_c/users/decompiler_user/AppData/Roaming/Relyze
COPY tools/relyze/decompiler_explorer.rb .
COPY decompile_relyze.py .
COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_relyze.py" ]

# rev.ng
FROM base-x86 AS revng
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install rev.ng
RUN cd / && curl -L -s 'https://rev.ng/downloads/revng-distributable/master/install.sh' | bash

USER decompiler_user
WORKDIR /home/decompiler_user
COPY decompile_revng.py .

COPY entrypoint.sh .
COPY runner_generic.py .
ENTRYPOINT [ "./entrypoint.sh", "decompile_revng.py" ]
