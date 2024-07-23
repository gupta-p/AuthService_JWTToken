FROM openjdk:17-jdk-slim

VOLUME /tmp
EXPOSE 8080
COPY target/iaoauthserverROPC-0.0.1-SNAPSHOT.jar app.jar
RUN sh -c 'touch /app.jar'

ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=docker", "app.jar"]


