FROM eclipse-temurin:11-jre-alpine

RUN apk add --no-cache curl && \
    mkdir -p /opt && \
    curl -sSL https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.85/bin/apache-tomcat-9.0.85.tar.gz -o /tmp/tomcat.tar.gz && \
    tar -xzf /tmp/tomcat.tar.gz -C /opt && \
    mv /opt/apache-tomcat-9.0.85 /opt/tomcat && \
    rm /tmp/tomcat.tar.gz && \
    rm -rf /opt/tomcat/webapps/* /tmp/tomcat.tar.gz

COPY ./ROOT /opt/tomcat/webapps/ROOT/

ENV ENDPOINT_TOCKEN_POSTGRES=ENDPOINT_TOCKEN_POSTGRES \
    DATABASE_TOCKEN=DATABASE_TOCKEN \
    USERNAME_TOCKEN=USERNAME_TOCKEN \
    USERPASSWORD_TOCKEN=USERPASSWORD_TOCKEN \
    ENDPOINT_TOCKEN_REDIS=ENDPOINT_TOCKEN_REDIS

COPY entry.sh /conf/entry.sh
RUN chmod +x /conf/entry.sh
ENTRYPOINT ["/conf/entry.sh"]

EXPOSE 8080

CMD ["/opt/tomcat/bin/catalina.sh", "run"]
