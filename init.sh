#!/bin/sh
set -x
set -e
cd $(dirname $0)

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_log.sql

# index
mysql -h ${myhost} -P ${myport} -u ${myuser} -e 'create index `login_log_user_id_succeeded` on login_log (`user_id`, `succeeded`);'  ${mydb} 
mysql -h ${myhost} -P ${myport} -u ${myuser} -e 'create index `login_log_succeeded_ip` on login_log ( `succeeded`, `ip`);'           ${mydb} 
mysql -h ${myhost} -P ${myport} -u ${myuser} -e 'create index `login_log_ip` on `login_log` (`ip`);'       ${mydb} 
mysql -h ${myhost} -P ${myport} -u ${myuser} -e 'create index `users_login` on users (`login`);'           ${mydb} 

curl -o /dev/null http://localhost/init
