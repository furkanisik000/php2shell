FROM tomcat:9.0
# Enable the AJP connector (Ghostcat surface) for the lab target.
COPY server.xml /usr/local/tomcat/conf/server.xml
EXPOSE 8080 8009
CMD ["catalina.sh", "run"]
