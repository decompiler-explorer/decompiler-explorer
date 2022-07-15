FROM python:3.8-slim

RUN useradd -ms /bin/false backend_user

RUN mkdir /opt/decompiler_explorer \
    && chown backend_user:backend_user /opt/decompiler_explorer

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc libc6-dev curl \
    && rm -rf /var/lib/apt/lists/*

USER backend_user
WORKDIR /opt/decompiler_explorer

RUN pip install --user pipenv

ENV PATH=/home/backend_user/.local/bin:$PATH

COPY Pipfile.lock .
RUN pipenv sync

RUN mkdir media staticfiles

COPY manage.py .
COPY entrypoint.sh .
COPY templates templates
COPY static static
COPY decompiler_explorer decompiler_explorer
COPY explorer explorer

ENTRYPOINT [ "./entrypoint.sh" ]

EXPOSE 8000

CMD ["gunicorn", "--capture-output", "-w", "4", "--bind", "0.0.0.0:8000", "decompiler_explorer.wsgi"]
