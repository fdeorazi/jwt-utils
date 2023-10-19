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
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;



/**
 * Jar utility to generate token json web token through an issuer and a private key
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtils {
  private static final Logger log = LoggerFactory.getLogger(JwtTokenUtils.class);

  private static final String RSA = "RSA";

  private String projectId;
  private String serviceAccount;
  private String sharedSecret;
  private String base64privateKey;
  private String scope;
  private String signedJwt;
  private String targetServiceUrl;
  private String keyFile;
  private TargetTokenType targetTokenType;
  private String publicKeyFile;

  Properties props;


  public static JwtTokenUtilsBuilder builder() {
    return new JwtTokenUtilsBuilder();
  }

  JwtTokenUtils(JwtTokenUtilsBuilder builder) {
    this.projectId = builder.projectId;
    this.serviceAccount = builder.serviceAccount;
    this.sharedSecret = builder.sharedSecret;
    this.signedJwt = builder.signedJwt;
    this.targetServiceUrl = builder.targetServiceUrl;
    this.keyFile = builder.keyFile;
    this.scope = builder.scope;
    this.targetTokenType = builder.targetTokenType;
    this.publicKeyFile = builder.publicKeyFile;
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

  String readPrivateKey(String filePath) throws IOException {
    String content = readKey(filePath);

    content = content.replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "").replaceAll("\r\n|\n|\r", "");
    log.debug("Read key:\n'{}'", content);
    return content;
  }

  String readPublicKey(String filePath) throws IOException {
    String content = readKey(filePath);

    content = content.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "").replaceAll("\r\n|\n|\r", "");
    
    log.debug("Read key:\n'{}'", content);
    return content;
  }



  /**
   * Generate a self signed jwt for identity token Invoke gcp endpoint with generated jwt.
   *
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws IOException
   */
  @Cmd(param = "ssjwt")
  public String generateSelfSignedJwt()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    Assert.present(serviceAccount, "Service account cannot be null.");
    Assert.present(targetServiceUrl, "Target service url cannot be null.");
    Assert.notNull(targetTokenType, "Token type cannot be unspecified.");

    if (keyFile != null) {
      base64privateKey = readPrivateKey(keyFile);
    }

    Assert.present(base64privateKey, "Private key cannot be null");

    Map<String, Object> header = new HashMap<>();
    header.put("type", "JWT");
    header.put("alg", "RS256");

    Map<String, Object> claims = new HashMap<>();

    if (targetTokenType.equals(TargetTokenType.ACCESS_TOKEN)) {
      claims.put("scope",
          scope == null || scope.isBlank() ? JwtProps.GCP_OAUTH2_SCOPE.val() : scope);
    }

    if (targetTokenType.equals(TargetTokenType.ID_TOKEN)) {
      claims.put("target_audience", targetServiceUrl);
      claims.put("sub", serviceAccount);
      //claims.put("iss", "https://accounts.google.com");
      claims.put("iss", serviceAccount);
    }

    claims.put("aud", JwtProps.GCP_TOKEN_URL.val());
    //claims.put("aud", serviceAccount);
    claims.put("exp", Long.sum(System.currentTimeMillis() / 1000, 3599));
    claims.put("iat", System.currentTimeMillis() / 1000);

    byte[] keyDerFormat = Base64.getDecoder().decode(base64privateKey);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyDerFormat);
    KeyFactory keyFactory = KeyFactory.getInstance(RSA);
    PrivateKey privateKey = keyFactory.generatePrivate(spec);

    return Jwts.builder().setClaims(claims).setHeader(header)
        .signWith(SignatureAlgorithm.RS256, privateKey).compact();
  }

  /**
   * 
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws IOException
   * 
   *         create jwt token head { "typ" : "JWT", "alg" : "RS256" } claims { "issueat" : "now",
   *         "exp" : "1day", "aud" : "project_id" }
   */
  public String generateSelfSignedJwtNodeMcu()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    if (keyFile != null) {
      base64privateKey = readPrivateKey(keyFile);
    }

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(base64privateKey.getBytes());

    KeyFactory keyFactory = KeyFactory.getInstance(RSA);
    PrivateKey privateKey = keyFactory.generatePrivate(spec);

    Map<String, Object> header = new HashMap<>();
    header.put("typ", "JWT");
    header.put("alg", "RS256");

    return Jwts.builder().setIssuedAt(new Date(System.currentTimeMillis())) // now
        .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 86400000))) // 1 day
        .setAudience(this.projectId).setHeader(header)
        .signWith(SignatureAlgorithm.RS256, privateKey).compact();

  }

  /**
   * 
   *
   * @param signedJwt rs256 signed jwt
   * @return the finat gcp access token
   */
  String gcpToken(String signedJwt) {
    String idToken = null;
    try {

      URL url = new URL(JwtProps.GCP_TOKEN_URL.val());
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();

      conn.setRequestMethod("POST");
      conn.setRequestProperty("Accept", "*/*");
      conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      conn.setDoOutput(true);

      String payload = JwtProps.GCP_TOKEN_REQ_PAYLOAD.val() + signedJwt;
      conn.setRequestProperty("Content-Length", String.valueOf(payload.length()));
      byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
      try (OutputStream os = conn.getOutputStream()) {
        os.write(bytes, 0, bytes.length);
      }

      if (conn.getResponseCode() != 200) {
        String message = String.format("%s return error with%nstatus %s%nmessage %s",
            JwtProps.GCP_TOKEN_URL.val(), conn.getResponseCode(), conn.getResponseMessage());
        throw new RuntimeException(message);
      }

      try (BufferedInputStream bis = new BufferedInputStream(conn.getInputStream());
          ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

        byte[] buff = new byte[4096];
        int read = 0;

        while ((read = bis.read(buff)) != -1) {
          baos.write(buff, 0, read);
        }
        String response = new String(baos.toByteArray());
        int start = response.indexOf(":") + 2;
        int end = response.indexOf("\"", start);
        idToken = end != -1 ? response.substring(start, end) : response.substring(start);
        log.debug("Response {}", response);
      }
      conn.disconnect();
      return idToken;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * 
   * @param sjwt
   * @param sharedSecret
   * @return
   * @throws IllegalArgumentException if missed or invalid arguments
   * @throws JOSEException
   * @throws ParseException
   */
  @Cmd(param = "hs256-verify")
  public boolean verifyHs256Jwt() throws JOSEException, ParseException {
    Assert.present(signedJwt, "Miss required argument 'signed jwt'");
    Assert.present(sharedSecret, "Miss required argument 'shared secret'");

    log.trace("signedJwt: '{}', sharedSecret: '{}'", signedJwt, sharedSecret);
    if (signedJwt == null || !signedJwt.contains(".")) {
      throw new IllegalArgumentException("Invalid Jwt");
    }
    SignedJWT signedJwtObj = SignedJWT.parse(signedJwt);
    log.trace("signature: {}", signedJwtObj.getSignature());
    JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes(StandardCharsets.UTF_8));

    return signedJwtObj.verify(verifier);
  }



  @Cmd(param = "rs256-verify")
  public Boolean verifyRs256Jwt() throws JOSEException, ParseException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    Assert.present(signedJwt, "Miss required argument 'signed jwt'");
    Assert.present(publicKeyFile, "Miss required argument 'public key file'");

    // log.trace("signedJwt: '{}', public key: '{}'", signedJwt, );
    if (signedJwt == null || !signedJwt.contains(".")) {
      throw new IllegalArgumentException("Invalid Jwt");
    }
    SignedJWT signedJwtObj = SignedJWT.parse(signedJwt);

    String base64PublicKey = readPublicKey(publicKeyFile);

    log.info("{}", base64PublicKey);

    byte[] keyDerFormat = Base64.getDecoder().decode(base64PublicKey);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyDerFormat);
    KeyFactory keyFactory = KeyFactory.getInstance(RSA);
    PublicKey publicKey = keyFactory.generatePublic(spec);
    
    JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
    return signedJwtObj.verify(verifier);
  }

  /**
   * Generates an HMAC signed jwt.
   *
   * @param sharedSecret shared secret to sign and verify the hmac jwt.
   * @return the signed jwt
   */
  @Cmd(param = "hs256")
  public String generateHs256Jwt() {
    Assert.present(sharedSecret, "Shared secret cannot be null");
    Assert.atLeast(sharedSecret, 32);

    log.trace("sharedSecret: '{}'", sharedSecret);

    Map<String, Object> headers = new HashMap<>();
    headers.put("type", "JWT");
    headers.put("alg", "HS256");

    Map<String, Object> claims = new HashMap<>();
    claims.put("aud", this.projectId);
    Long now = System.currentTimeMillis() / 1000;
    claims.put("iat", now);
    claims.put("exp", now + 86400);


    return Jwts.builder().setHeader(headers).setClaims(claims)
        .signWith(SignatureAlgorithm.HS256, sharedSecret.getBytes(StandardCharsets.UTF_8))
        .compact();
  }

  @Cmd(param = {"idtoken", "access-token"})
  public String generateToken()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    String ssjwt = generateSelfSignedJwt();
    PrintUtility.prettyPrintJwt(ssjwt);
    return gcpToken(ssjwt);
  }

}
