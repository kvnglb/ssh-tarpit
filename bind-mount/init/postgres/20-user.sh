#!/bin/bash

psql -U postgres -c "ALTER USER ssh PASSWORD '$POSTGRES_SSH_PASSWORD';"
