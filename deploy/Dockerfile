FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY auth-core/pom.xml auth-core/pom.xml
COPY auth-adapters/pom.xml auth-adapters/pom.xml
COPY auth-app/pom.xml auth-app/pom.xml
RUN mvn -B -q -pl auth-core,auth-adapters,auth-app dependency:go-offline || true
COPY . .
RUN mvn -B -q -pl auth-app -am package -DskipTests

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S synkro && adduser -S synkro -G synkro
COPY --from=build /src/auth-app/target/auth-app-*.jar /app/auth-app.jar
USER synkro
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/auth-app.jar"]
