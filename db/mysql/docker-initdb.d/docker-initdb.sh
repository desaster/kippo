#!/bin/sh

set -e

MYSQL="mariadb -u root -p$MARIADB_ROOT_PASSWORD"

echo "GRANT ALL PRIVILEGES ON $MARIADB_DATABASE.* TO $MARIADB_USER;" | $MYSQL

$MYSQL "$MARIADB_DATABASE" < /sql-scripts/mysql.sql
