FROM nginx:alpine

RUN rm -rf /usr/share/nginx/html

COPY ./frontend/build/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/nginx.conf
ENV DOMAIN_TOCKEN=DOMAIN_TOCKEN
COPY entry.sh /conf/entry.sh
RUN chmod +x /conf/entry.sh
ENTRYPOINT ["/conf/entry.sh"]

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;", "-c", "/etc/nginx/nginx.conf"]
