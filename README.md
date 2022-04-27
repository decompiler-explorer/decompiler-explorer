# Decompiler Explorer

[Decompiler Explorer](https://dogbolt.org) is a web front-end to a number of [decompilers](/runners/decompiler), allowing for quick comparison of decompilation output and analysis time. 


![Decompiler Explorer](/static/img/preview.png) (early preview image)

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


## Starting dev server
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


## Running in docker (dev)
```shell
python scripts/dce.py start
```


## Running in docker (production)
```shell
python scripts/dce.py start --prod --acme-email=<your email>
```


## Running in docker (production with s3 storage)
```shell
python scripts/dce.py start --prod --acme-email=<your email> --s3-bucket=<s3 bucket name>
```
