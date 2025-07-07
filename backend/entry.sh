#!/bin/sh
set -e
INDEX_CACHE=$(find /opt/tomcat/webapps/ROOT/WEB-INF/classes/ -type f -name "cache.properties" | head -n 1)
INDEX_HYBERNATE=$(find /opt/tomcat/webapps/ROOT/WEB-INF/classes/ -type f -name "hibernate.properties" | head -n 1)
echo "Found file: ${INDEX_CACHE}"
if [ -n "${INDEX_CACHE}" ] && [ -f "${INDEX_CACHE}" ]; then
    sed -i "s|ENDPOINT_TOCKEN_REDIS|${ENDPOINT_TOCKEN_REDIS}|g" ${INDEX_CACHE}

else
    echo "File index..js not found!"
fi

if [ -n "${INDEX_HYBERNATE}" ] && [ -f "${INDEX_HYBERNATE}" ]; then
    sed -i -e "s|ENDPOINT_TOCKEN_POSTGRES|${ENDPOINT_TOCKEN_POSTGRES}|g" \
	   -e "s|DATABASE_TOCKEN|${DATABASE_TOCKEN}|g" \
	   -e "s|USERNAME_TOCKEN|${USERNAME_TOCKEN}|g" \
           -e "s|USERPASSWORD_TOCKEN|${USERPASSWORD_TOCKEN}|g" ${INDEX_HYBERNATE}

else
    echo "File index..js not found!"
fi

exec "$@"
