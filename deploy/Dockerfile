FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY auth-core/pom.xml auth-core/pom.xml
COPY auth-adapters/pom.xml auth-adapters/pom.xml
COPY auth-app/pom.xml auth-app/pom.xml
COPY auth-coverage/pom.xml auth-coverage/pom.xml
RUN mvn -B -q -pl auth-core,auth-adapters,auth-app dependency:go-offline || true
COPY . .
RUN mvn -B -q -pl auth-app -am package -DskipTests

FROM eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474
RUN apk upgrade --no-cache && apk del gnupg
RUN addgroup -S synkro && adduser -S synkro -G synkro
COPY --from=build /src/auth-app/target/auth-app-*.jar /app/auth-app.jar
USER synkro
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/auth-app.jar"]
