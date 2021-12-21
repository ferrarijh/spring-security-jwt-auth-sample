# spring-security-jwt-auth-sample
Sample project demonstrating authentication and jwt authorization with Spring Security.
Features JPA and MySQL DB(with docker-compose).

## How to simulate
1. Start docker daemon.
2. Run task `bootJar` in project to build fat jar. For instance, execute `gradlew bootJar` command.
3. Execute docker compose yml file.
4. Test with preferred clients like Postman.