FROM python:3.9.16-bullseye

WORKDIR /ssh

RUN pip install --user psycopg2-binary

COPY main.py .

ENTRYPOINT [ "python", "-u", "./main.py" ]
