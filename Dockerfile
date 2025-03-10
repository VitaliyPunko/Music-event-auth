FROM openjdk:17-jdk-slim

WORKDIR /app

COPY build/libs/music-event-auth.jar app.jar

EXPOSE 9000

ENTRYPOINT ["java", "-jar", "app.jar"]


