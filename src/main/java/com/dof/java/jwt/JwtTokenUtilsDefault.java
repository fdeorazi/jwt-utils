/*
 * Copyright 2023 Fabio De Orazi
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.dof.java.jwt;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.crypto.CryptoFunctions;
import com.dof.java.jwt.enums.JwtProps;
import com.dof.java.jwt.enums.TargetTokenType;
import com.dof.java.jwt.exception.JwtTokenUtilsException;
import com.dof.java.jwt.exception.RequestTokenHttpException;
import com.google.gson.Gson;

/**
 * Jar utility to generate token JSON Web Token through an issuer and a private key.
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsDefault implements JwtTokenUtils {
  private static final Logger log = LoggerFactory.getLogger(JwtTokenUtilsDefault.class);

  private static final String RSA = "RSA";

  private String serviceAccount;
  private String sharedSecret;
  private String base64privateKey;

  private String signedJwt;
  private String targetServiceUrl;
  private String keyFile;
  private TargetTokenType targetTokenType;
  private String publicKeyFile;
  private boolean verbose;

  private String issuer;
  private String subject;
  private String audience;
  private String targetAdience;
  private String scope;
  private Integer expireIn;

  Properties props;

  JwtTokenUtilsDefault(JwtTokenUtilsBuilder builder) {
    this.serviceAccount = builder.getServiceAccount();
    this.sharedSecret = builder.getSharedSecret();
    this.signedJwt = builder.getSignedJwt();
    this.targetServiceUrl = builder.getTargetServiceUrl();
    this.keyFile = builder.getKeyFile();
    this.scope = builder.getScope();
    this.targetTokenType = builder.getTargetTokenType();
    this.publicKeyFile = builder.getPublicKeyFile();
    this.verbose = builder.isVerbose();
    this.base64privateKey = builder.getBase64privateKey();
    this.issuer = builder.getIssuer();
    this.subject = builder.getSubject();
    this.audience = builder.getAudience();
    this.targetAdience = builder.getTargetAdience();
    this.expireIn = builder.getExpireIn();
  }

  private String readKey(String filePath) throws IOException {
    File key = new File(filePath);

    // test purpose: search key inside sources
    if (!key.exists()) {

      URL url = this.getClass().getClassLoader().getResource(filePath);
      if (url != null) {
        filePath = url.getPath();
        key = new File(filePath);
      }
    }

    if (!key.exists()) {
      throw new IOException("Key not found");
    }
    String content;
    try (InputStream in = new FileInputStream(key)) {
      byte[] buff = new byte[4096];
      int read;
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      while ((read = in.read(buff)) != -1) {
        baos.write(buff, 0, read);
      }
      content = new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }
    return content;
  }

  /**
   * Given private key file path it reads content and remove key header and footer. For this method
   * the key must be in PEM format.
   *
   * @param filePath The file path of private key.
   * @return the private key content
   */
  public String readPrivateKey(String filePath) throws IOException {
    String content = readKey(filePath);

    content = content.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "").replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "").replaceAll("\r\n|\n|\r", "");
    log.trace("Private key:\n{}\n", content);
    return content;
  }

  /**
   * Return private key in java representation {@link PrivateKey}.
   *
   * @param filePath private key path
   * @param algorithm which will be used in java conversion
   * @return private key
   * @throws NoSuchAlgorithmException if passed algorithm not found
   * @throws InvalidKeySpecException if invalid key specification
   * @throws IOException if private key file not found
   */
  public PrivateKey readPrivateKey(String filePath, String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    byte[] keyDerFormat = Base64.getDecoder().decode(readPrivateKey(filePath));
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyDerFormat, algorithm);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    return keyFactory.generatePrivate(spec);
  }

  /**
   * Given public key file path (in PEM format) it reads content and removes header and footer.
   *
   * @param filePath The file path of private key.
   * 
   */
  public String readPublicKey(String filePath) throws IOException {
    String content = readKey(filePath);

    content = content.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "").replaceAll("\r\n|\n|\r", "");

    log.debug("Public key:\n{}", content);
    return content;
  }

  /**
   * Reads public key from file system and return.
   *
   * @param filePath The path of the key file.
   * @param algorithm the name of the key algorithm
   * @return {@link PublicKey}
   * @throws IOException if key file not found
   * @throws NoSuchAlgorithmException if algorithm not found
   * @throws InvalidKeySpecException
   */
  public PublicKey readPublicKey(String filePath, String algorithm)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] keyDerFormat = Base64.getDecoder().decode(readPublicKey(filePath));
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyDerFormat);
    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    return keyFactory.generatePublic(spec);
  }


  @Override
  public String generateSelfSignedJwt() {
    Assert.notNull(targetTokenType, "Miss required argument 'token type'");
    if (!Assert.present(issuer) && !Assert.present(serviceAccount)) {
      throw new IllegalArgumentException("For signed JWT issuer or service account are required.");
    }

    if (targetTokenType.equals(TargetTokenType.ID_TOKEN)) {
      if (!Assert.present(subject) && !Assert.present(serviceAccount) && log.isWarnEnabled()) {
        log.warn(JwtProps.SSJWT_MISS_SUB.val());
      }
      if (!Assert.present(targetAdience) && !Assert.present(targetServiceUrl)) {
        throw new IllegalArgumentException(JwtProps.SSJWT_MISS_TARGET_AUDIENCE.val());
      }
    }

    try {
      if (keyFile != null) {
        base64privateKey = readPrivateKey(keyFile);
      }

      Assert.present(base64privateKey, "Miss required argument 'private key'");

      Map<String, Object> header = new HashMap<>();
      header.put("type", "JWT");
      header.put("alg", "RS256");

      Map<String, Object> claims = new HashMap<>();

      if (targetTokenType.equals(TargetTokenType.ACCESS_TOKEN)) {
        claims.put("scope", Assert.present(scope) ? scope : JwtProps.GCP_OAUTH2_SCOPE.val());

      } else if (targetTokenType.equals(TargetTokenType.ID_TOKEN)) {
        claims.put("target_audience",
            Assert.present(targetAdience) ? targetAdience : targetServiceUrl);
        claims.put("sub", Assert.present(subject) ? subject : serviceAccount);
      }

      claims.put("aud", Assert.present(audience) ? audience : JwtProps.GCP_TOKEN_URL.val());
      claims.put("iss", Assert.present(issuer) ? issuer : serviceAccount);
      claims.put("exp", Long.sum(System.currentTimeMillis() / 1000,
          (this.expireIn != null ? this.expireIn : 3599)));
      claims.put("iat", System.currentTimeMillis() / 1000);

      byte[] keyDerFormat = Base64.getDecoder().decode(base64privateKey);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyDerFormat);
      KeyFactory keyFactory = KeyFactory.getInstance(RSA);
      PrivateKey privateKey = keyFactory.generatePrivate(spec);

      Gson gson = new Gson();
      String jsonHeader = gson.toJson(header);
      String base64Header = new String(Base64.getEncoder().encode(jsonHeader.getBytes()));
      String jsonClaims = gson.toJson(claims);
      String base64Claims = new String(Base64.getEncoder().encode(jsonClaims.getBytes()));

      String jwt = String.format("%s.%s", base64Header, base64Claims);

      byte[] signature = CryptoFunctions.signRsa256(jwt, privateKey);

      String base64Signature = new String(Base64.getEncoder().encode(signature));

      log.debug("Base64 signature:\n'{}'\n", base64Signature);

      String sjwt = String.format("%s.%s", jwt, base64Signature);

      if (verbose) {
        PrintUtility.indentJwt(sjwt, "Generated self signed token ");
      }
      return sjwt;

    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }
  }

  @Override
  public String gcpToken() {
    Assert.present(signedJwt);

    String idToken = null;
    try {

      URL url = new URL(JwtProps.GCP_TOKEN_URL.val());
      String grantType = JwtProps.GCP_TOKEN_REQ_PAYLOAD.val();
      String payload = "grant_type=".concat(URLEncoder.encode(grantType, StandardCharsets.UTF_8))
          .concat("&assertion=").concat(URLEncoder.encode(signedJwt, StandardCharsets.UTF_8));


      byte[] postData = payload.getBytes(StandardCharsets.UTF_8);

      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
      conn.setRequestMethod("POST");
      conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      conn.setRequestProperty("charset", "utf-8");
      conn.setRequestProperty("Content-Length", Integer.toString(postData.length));

      conn.setDoOutput(true);
      conn.setInstanceFollowRedirects(false);
      conn.setUseCaches(false);


      if (verbose) {
        StringBuilder sb = new StringBuilder();
        sb.append(
            String.format("%n%s%s%n", JwtProps.CMD_COLOR1.val(), "Invoke token request endpoint"));
        sb.append(String.format("%s%s%n", JwtProps.CMD_COLOR5.val(), "Url"));
        sb.append(String.format("%s%s%n", JwtProps.CMD_COLOR3.val(), url));
        sb.append(String.format("%s%-10s%s%n", JwtProps.CMD_COLOR5.val(), "Payload",
            JwtProps.CMD_COLOR0.val()));
        sb.append(JwtProps.CMD_COLOR3.val());
        sb.append(payload.concat("\n"));
        log.info("{}", sb);
        sb.append(JwtProps.CMD_COLOR0.val());
      }

      try (OutputStream os = conn.getOutputStream()) {
        os.write(postData, 0, postData.length);
      }

      if (conn.getResponseCode() != 200) {
        String error = readFromStream(conn.getErrorStream());
        String message = String.format("%s return HTTP %s %s %s", JwtProps.GCP_TOKEN_URL.val(),
            conn.getResponseCode(), conn.getResponseMessage(), error);

        throw new RequestTokenHttpException(message);
      }

      String response = readFromStream(conn.getInputStream());
      int start = response.indexOf(":") + 2;
      int end = response.indexOf("\"", start);
      idToken = end != -1 ? response.substring(start, end) : response.substring(start);
      if (verbose) {
        log.info("Response {}", response);
      }
      conn.disconnect();

      if (this.verbose && targetTokenType.equals(TargetTokenType.ID_TOKEN)) {
        PrintUtility.indentJwt(idToken, "\nReturned ID Token from GCP ");
      }

      return idToken;
    } catch (RequestTokenHttpException e) {
      throw e;
    } catch (Exception e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }
  }

  String readFromStream(InputStream in) throws IOException {
    try (BufferedInputStream bis = new BufferedInputStream(in);
        ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

      byte[] buff = new byte[4096];
      int read = 0;

      while ((read = bis.read(buff)) != -1) {
        baos.write(buff, 0, read);
      }
      return new String(baos.toByteArray());
    }
  }


  @Override
  public boolean verifyHs256Jwt() {
    Assert.present(signedJwt, "Miss required argument 'signed jwt'");
    Assert.present(sharedSecret, "Miss required argument 'secret'");
    try {
      log.trace("signedJwt: '{}', sharedSecret: '{}'", signedJwt, sharedSecret);
      if (signedJwt == null || !signedJwt.contains(".")) {
        throw new IllegalArgumentException("Invalid Jwt");
      }
      return CryptoFunctions.verifyJwtSignature(signedJwt, sharedSecret);

    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }
  }

  @Override
  public boolean verifyRs256Jwt() {
    Assert.present(signedJwt, "Miss required argument 'signed jwt'");
    Assert.present(publicKeyFile, "Miss required argument 'public key file'");
    boolean verified = false;
    try {

      if (signedJwt == null || !signedJwt.contains(".")) {
        throw new IllegalArgumentException("Invalid Jwt");
      }

      String base64PublicKey = readPublicKey(publicKeyFile);

      log.info("{}", base64PublicKey);

      byte[] keyDerFormat = Base64.getDecoder().decode(base64PublicKey);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyDerFormat);
      KeyFactory keyFactory = KeyFactory.getInstance(RSA);
      PublicKey publicKey = keyFactory.generatePublic(spec);

      verified = CryptoFunctions.verifyJwtSignature(signedJwt, publicKey);

    } catch (NumberFormatException | IOException | NoSuchAlgorithmException
        | InvalidKeySpecException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }

    return verified;
  }

  @Override
  public String generateHs256Jwt() {
    Assert.present(sharedSecret, "Miss required parameter 'secret'");
    Assert.atLeast(sharedSecret, 32);

    Map<String, Object> headers = new HashMap<>();
    headers.put("type", "JWT");
    headers.put("alg", "HS256");

    Map<String, Object> claims = new HashMap<>();
    claims.put("aud", this.audience);
    Long now = System.currentTimeMillis() / 1000;
    claims.put("iat", now);
    claims.put("exp", now + (this.expireIn != null ? this.expireIn : 86400));

    Gson gson = new Gson();
    String jsonHeader = gson.toJson(headers);
    String base64Header = new String(Base64.getEncoder().encode(jsonHeader.getBytes()));
    String jsonClaims = gson.toJson(claims);
    String base64Claims = new String(Base64.getEncoder().encode(jsonClaims.getBytes()));

    String jwt = String.format("%s.%s", base64Header, base64Claims);

    byte[] signature;
    try {
      signature = CryptoFunctions.signHs256(jwt, sharedSecret);
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }

    String base64Signature = new String(Base64.getEncoder().encode(signature));

    String sjwt = String.format("%s.%s", jwt, base64Signature);

    if (verbose) {
      PrintUtility.indentJwt(jwt, "Generated self signed token ");
    }
    return sjwt;
  }

  @Override
  public String generateToken() {
    this.signedJwt = generateSelfSignedJwt();
    return gcpToken();
  }

}
