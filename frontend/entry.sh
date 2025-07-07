#!/bin/sh
set -e
INDEX_JS_FILE=$(find /usr/share/nginx/html/static/js -type f -name "main.*.js" | head -n 1)
echo "Found file: ${INDEX_JS_FILE}"
if [ -n "${INDEX_JS_FILE}" ] && [ -f "${INDEX_JS_FILE}" ]; then
    sed -i "s|DOMAIN_TOCKEN|${DOMAIN_TOCKEN}|g" ${INDEX_JS_FILE} 

else
    echo "File index..js not found!"
fi

exec "$@"
