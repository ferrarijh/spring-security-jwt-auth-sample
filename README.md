# spring-security-jwt-auth-sample
Sample project demonstrating authentication and jwt authorization with Spring Security.
Features JPA and MySQL DB(with docker-compose).

Upon the app's execution via docker compose, three tables will be generated: 

`user`, `user_role`, `role`

where `user_role` is junction table which plays critical role in many-to-many relationship 
between `user` table and `role` table.

## How to simulate
1. Start docker daemon.
2. Run task `bootJar` in project to build fat jar. For instance, execute `gradlew bootJar` command.
3. Execute docker compose yml file.
4. Test with preferred clients like Postman.