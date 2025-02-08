FROM openjdk:17-alpine

COPY ./target/springsecurity-v1.jar app.jar

ENTRYPOINT ["java", "-jar", "/app.jar"]

EXPOSE 8080