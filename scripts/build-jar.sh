jarName=jwt-utils.jar
mvn clean package &&
echo Class-Path: $(for i in $(ls target/lib); do printf "lib/$i "; done) > target/manifest-info &&
jar -cfem target/$jarName com.dof.java.jwt.JWTTokenUtils target/manifest-info -C target/classes com/dof/java/jwt/JWTTokenUtils.class &&
tar -cf target/jwt_utils.tar -C target $jarName lib
mvn install
