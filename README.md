# Jwt Utils Project
## Overview
Json Web Token Utilities written to create self signed JWT iam to request Identity or Access Tokens to a cloud provider. It allows follow functionalities:

* Create a self signed HS256 or RS256 Json Web Token
* Create a self signed JWT
* Verify signature for HS256 or RS256 signed JWT
* Request an Identity Token (OpenID compliant) to Cloud enpoint through selft signed JWT
* Request an opaque Oauth2 Access Token to Cloud enpoint through self signed JWT

#### Signature
##### Supported Digest Algorithms
* SHA256
##### Supported Encrypt Algorithms
* HMAC
* RSA
#### Token Request
##### Supported Cloud Provider
* Google Cloud Platform
#### Java
##### Supported Java Version
Java 11 or later
## Configuration
#### Clone
Clone this repository
```
git clone https://github.com/FabioDoF/jwt-utils.git
```
#### Build
###### Jar with external lib
Build with maven a Jar with dependecies on /lib folder
```
cd jwt-utils
mvn -Dmaven.test.skip clean install
```
###### Fat Jar
Build a jar with all dependecies classes inside. With this archive is not need to bring /lib folder
when moving the application jar archive.
```
mvn -Dmaven.test.skip clean install -P fatjar
```

## Usage
#### From Command Line
###### Help Menu
```
java -jar target/jwt-utils.jar --help
```
![Alt text](screen/jwt-token-utils-help.png)
###### Generate an HS256 signed Jwt
```
java -jar target/jwt-utils.jar --secret <hmac-256bit-ascii-secret> -v
```
![Alt text](screen/jwt-token-utils-hs256-verbose.png)
#### From Java existing project
##### Dependency
Add follow dependency in pom.xml file
```
<dependency>
    <groupId>com.dof.java.jwt</groupId>
    <artifactId>jwt-utils</artifactId>
    <version>1.0.0</version>
</dependency>
```
##### In Java Code
###### Generate a RS256 signed Jwt
Generation of a JWT to request an Oauth2 Access Token with scope https://www.googleapis.com/auth/pubsub for Google PubSub authorization.
```
String accessToken = JwtTokenUtilsInit.builder().setServiceAccount(
    "service-account-example@project-example.iam.gserviceaccount.com")
    .setBase64PrivateKey(privateKey)
    .setScope("https://www.googleapis.com/auth/pubsub")
    .setTargetTokenType(TargetTokenType.ACCESS_TOKEN)
    .build()
    .generateSelfSignedJwt();
```
Then for example we can use it like follow:

```
curl -X POST https://pubsub.googleapis.com/v1/projects/project-id/topics/topic-id:publish \
  -H 'Authorization: Bearer: <access-token>'
  -H 'Content-Type: application/json'
```

