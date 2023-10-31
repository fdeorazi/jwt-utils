# Jwt Utils Project
## Overview
An utility to create and verify self signed Json Web Tokens and also request with them, an access token to an authorization server.

I've initially developer this tool for personal usage in my Google Cloud projects and to better understand JWT, Java Cryptography Architecture (JCA) and service authentication on Google Cloud.

It allows follow functionalities:
* Create and verify a self signed HS256 or RS256 Json Web Token
* Obtain an Identity Token (OpenID Connect compliant) via Cloud enpoint with selft signed JWT
* Obtain an Oauth2 Access Token via Cloud enpoint through self signed JWT

Reference to Self Signed JWT on Google Cloud Platform:
* https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-jwt
* https://developers.google.com/identity/protocols/oauth2/service-account


### Signature
##### Supported Signature Algorithms
* HS256
* RS256
### Token Request
##### Supported Cloud Provider
* Google Cloud Platform
### Java
##### Supported Java Version
Java 11 or later
## Configuration
#### Clone
Clone this repository
```
git clone https://github.com/FabioDoF/jwt-utils.git
```
### Build
###### Jar with external lib
Build with maven a Jar with dependecies on lib folder
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
### From Command Line
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
### From Java existing project
##### Dependency
Add follow dependency in pom.xml file
```
<dependency>
    <groupId>com.dof.java.jwt</groupId>
    <artifactId>jwt-utils</artifactId>
    <version>1.0.0</version>
</dependency>
```
#### In Java Code
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
## Author

**Fabio De Orazi**

* https://www.linkedin.com/in/fabio-de-orazi-a2863596
## Copyright and license

The code is released under the [Apache license](LICENSE?raw=true).

---------------------------------------

