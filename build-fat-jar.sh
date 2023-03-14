mvn clean install &&
for i in $(ls target/lib); do tar -xf target/lib/$i  -C  target/classes; done &&
jar -cfem target/jwt-utils-1.0.jar com.dof.java.jwt.JWTTokenUtils -C target/classes com/dof/java/jwt/JWTTokenUtils.class
