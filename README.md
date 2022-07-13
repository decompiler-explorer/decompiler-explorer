# Decompiler Explorer

[Decompiler Explorer](https://dogbolt.org) is a web front-end to a number of [decompilers](/runners/decompiler). This web service lets you compare the output of different decompilers on small executables. In other words: It's basically the same thing as Matt Godbolt's awesome [Compiler Explorer](https://github.com/compiler-explorer/compiler-explorer), but in reverse.


![Decompiler Explorer](/static/img/preview.png)

## Prerequisites
- python >= 3.8
- pipenv
- docker
- docker-compose


## Installation
```
pipenv install
python scripts/dce.py init
```


## Setting up decompilers
See the instructions [here](runners/decompiler/tools/README.md)


## Running in docker (dev)
```shell
pipenv install
python scripts/dce.py init

# Build all decompilers with valid keys 
python scripts/dce.py build
# If you want to exclude certain decompilers
# python scripts/dce.py --without-reko build

python scripts/dce.py start
# UI now accessible on port 80/443
```


## Running in docker (production)
```shell
python scripts/dce.py start --prod --replicas 2 --acme-email=<your email>
```


## Running in docker (production with s3 storage)
```shell
python scripts/dce.py start --prod --acme-email=<your email> --s3-bucket=<s3 bucket name>
```

## Starting dev server (outside Docker)
> This won't start any decompilers, just the frontend

```shell
pipenv run python manage.py migrate
pipenv run python manage.py runserver 0.0.0.0:8000
```


## Starting decompiler for dev server
```shell
export EXPLORER_URL=http://172.17.0.1:8000

docker-compose up binja --build --force-recreate --remove-orphans
```
