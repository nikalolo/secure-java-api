# BASELINE Dockerfile — deliberately naive (Task 1).
# We scan it as-is first, then harden it in Phase 2.

# Base image: provides the OS and a Java runtime.
FROM openjdk:17

# Copy the JAR that Maven built (target/app.jar) into the image.
COPY target/app.jar /app.jar

# Document the port the app listens on (does not publish it by itself).
EXPOSE 8080

# Command that runs when a container starts.
ENTRYPOINT ["java", "-jar", "/app.jar"]
