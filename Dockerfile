# BASELINE Dockerfile — deliberately naive (Task 1).
# We scan it as-is first, then harden it in Phase 2.

# Base image: provides the OS and a Java runtime.
#
# Was `FROM openjdk:17`. That tag no longer exists on Docker Hub (2026-11-02):
#   ERROR: failed to build: failed to solve: openjdk:17: failed to resolve source
#   metadata for docker.io/library/openjdk:17: docker.io/library/openjdk:17: not found
# (Hub API: GET /v2/repositories/library/openjdk/tags/17 -> HTTP 404.)
# 17.0.2 is the newest JDK 17 tag Docker Hub ever published (last updated
# 2022-04-28), i.e. the last build `17` could have pointed to. It is still
# deprecated, unpatched, root and full JDK: this is NOT hardening, just keeping
# the "before" image buildable. See docs/baseline-scan.md.
FROM openjdk:17.0.2

# Copy the JAR that Maven built (target/app.jar) into the image.
COPY target/app.jar /app.jar

# Document the port the app listens on (does not publish it by itself).
EXPOSE 8080

# Command that runs when a container starts.
ENTRYPOINT ["java", "-jar", "/app.jar"]
