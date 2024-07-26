FROM python:3.12.4-bookworm

WORKDIR /ssh

RUN pip install --user psycopg2-binary

COPY main.py .

ENTRYPOINT [ "python", "-u", "./main.py" ]
