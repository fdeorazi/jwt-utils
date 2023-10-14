package com.dof.java.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.LogManager;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * Jar utility to generate token json web token through an issuer and a private key
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtils {
  private static final Logger log = LoggerFactory.getLogger(JwtTokenUtils.class);

  private static final String DEFAULT_OAUTH2_SCOPE =
      "https://www.googleapis.com/auth/cloud-platform";
  private static final String GCP_TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token";

  private static final String RSA = "RSA";
  private static final String TARGET_AUDIENCE = "https://iotserver-wr-jbywjzjd6a-oc.a.run.app";


  private byte[] pkcs8privatekey;
  private String projectId;
  private String serviceAccount;
  private String base64privateKey;
  private String sharedSecret;
  private String scope;
  private String signedJwt;


  

  public static JwtTokenUtilsBuilder builder() {
    return new JwtTokenUtilsBuilder();
  }

  JwtTokenUtils(JwtTokenUtilsBuilder builder) {
    this.projectId = builder.projectId;
    this.serviceAccount = builder.serviceAccount;
    this.sharedSecret = builder.sharedSecret;
    this.signedJwt = builder.signedJwt;
  }


  // LOGGING CONFIG
  static {
    loggingConf();
  }



  /**
   * Constructor with basic argument to use in various methods.
   *
   * @param base64privateKey privateKey in PEM format
   * @param serviceAccount gcp service account to issue and sign the jwt
   */
  private JwtTokenUtils(String base64privateKey, String serviceAccount) {
    this.pkcs8privatekey = Base64.getDecoder().decode(base64privateKey);
    if (serviceAccount != null && !serviceAccount.isEmpty()) {
      this.serviceAccount = serviceAccount;
    }
  }


  static String readPrivateKey(String filePath) throws IOException {
    File key = new File(filePath);
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
    content = content.replace("\n", "");
    return content;
  }

  /**
   * 
   * @param scope
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws IOException
   */
  public String generateSelfSignedJwtForAccessToken(String scope)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

    Map<String, Object> header = new HashMap<>();
    header.put("type", "JWT");
    header.put("alg", "RS256");

    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", serviceAccount);
    claims.put("scope", scope == null || scope.isBlank() ? DEFAULT_OAUTH2_SCOPE : scope);
    claims.put("aud", "https://oauth2.googleapis.com/token");
    claims.put("exp", Long.sum(System.currentTimeMillis() / 1000, 3599));
    claims.put("iat", System.currentTimeMillis() / 1000);

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8privatekey);
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
   */
  public String generateSelfSignedJwtForIdToken()
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    Map<String, Object> header = new HashMap<>();
    header.put("type", "JWT");
    header.put("alg", "RS256");

    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", serviceAccount);
    claims.put("sub", serviceAccount);
    claims.put("aud", GCP_TOKEN_URL);
    claims.put("target_audience", TARGET_AUDIENCE);
    claims.put("exp", Long.sum(System.currentTimeMillis() / 1000, 3599));
    claims.put("iat", System.currentTimeMillis() / 1000);

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8privatekey);
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

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8privatekey);

    KeyFactory keyFactory = KeyFactory.getInstance(RSA);
    PrivateKey privateKey = keyFactory.generatePrivate(spec);

    Map<String, Object> header = new HashMap<>();
    header.put("typ", "JWT");
    header.put("alg", "RS256");

    return Jwts.builder().setIssuedAt(new Date(System.currentTimeMillis())) // now
        // .setIssuedAt(new Date((System.currentTimeMillis() - 86400000))) // 1 day ago
        .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 86400000))) // 1 day
        // .setExpiration(new Date(Long.sum(System.currentTimeMillis(), 59000))) // 59
        // seconds
        .setAudience(this.projectId).setHeader(header)
        .signWith(SignatureAlgorithm.RS256, privateKey).compact();

  }

  /**
   * 
   *
   * @param signedJwt rs256 signed jwt
   * @return the finat gcp access token
   */
  public String gcpToken(String signedJwt) {
    String idToken = null;
    try {

      URL url = new URL(GCP_TOKEN_URL);
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();

      conn.setRequestMethod("POST");
      conn.setRequestProperty("Accept", "*/*");
      conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      conn.setDoOutput(true);

      String payload =
          "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + signedJwt;
      conn.setRequestProperty("Content-Length", String.valueOf(payload.length()));
      byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
      try (OutputStream os = conn.getOutputStream()) {
        os.write(bytes, 0, bytes.length);
      }

      if (conn.getResponseCode() != 200) {
        String message = String.format("%s return error with%nstatus %s%nmessage %s", GCP_TOKEN_URL,
            conn.getResponseCode(), conn.getResponseMessage());
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
   * @throws ParseException
   * @throws JOSEException
   */
  public boolean verifyHs256Jwt() throws ParseException, JOSEException {
    Objects.requireNonNull(signedJwt);
    Objects.requireNonNull(sharedSecret);

    log.trace("signedJwt: '{}', sharedSecret: '{}'", signedJwt, sharedSecret);
    if (signedJwt == null || !signedJwt.contains(".")) {
      throw new ParseException("Invalid Jwt", 0);
    }
    SignedJWT signedJwtObj = SignedJWT.parse(signedJwt);
    log.trace("signature: {}", signedJwtObj.getSignature());
    JWSVerifier verifier = new MACVerifier(sharedSecret.getBytes(StandardCharsets.UTF_8));
    return signedJwtObj.verify(verifier);
  }

  /**
   * Generates an HMAC signed jwt.
   *
   * @param sharedSecret shared secret to sign and verify the hmac jwt.
   * @return the signed jwt
   */
  public String generateHs256Jwt() {
    Assert.notNull(sharedSecret, "Shared secret cannot be null");
    log.trace("sharedSecret: '{}'", sharedSecret);

    Map<String, Object> headers = new HashMap<>();
    headers.put("type", "JWT");
    headers.put("alg", "HS256");

    Map<String, Object> claims = new HashMap<>();
    claims.put("aud", this.projectId);
    claims.put("iat", 1661983200);
    claims.put("exp", 1664488800);


    return Jwts.builder().setHeader(headers).setClaims(claims)
        .signWith(SignatureAlgorithm.HS256, sharedSecret.getBytes(StandardCharsets.UTF_8))
        .compact();
  }

  /**
   * Application entry point.
   *
   * @param args application arguments
   */
  public static void main(String... args) {

    try {
      if (args == null || args.length < 2) {
        log.info("No argument passed.");
        printHelp();
        return;
      }


      log.debug("Passed arguments: {}", args.length);
      Arrays.stream(args).forEach(arg -> {
        log.debug("{}\n", arg);
      });

      evalMethod(args);

    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

  }

  static final String KEY_FILE = "-keyfile";
  static final String RS256 = "-rs256";
  static final String ID_TOKEN = "-gcpIdToken";
  static final String ACCESS_TOKEN = "-accessToken";
  static final String HS256 = "-hs256";
  static final String HS256_VERIFY = "-hs256verify";

  static final String PROJECT_ID = "iot-weather-station-project";

  private static void evalMethod(String... args) throws NoSuchAlgorithmException,
      InvalidKeySpecException, IOException, ParseException, JOSEException {
    String finalJwt;
    if (args.length >= 2 && args[0].equals(HS256) && args[1] != null) {
      finalJwt = JwtTokenUtils.builder().setSharedSecret(args[1]).build().generateHs256Jwt();
      if (logVerbose(args)) {
        jwtVerbose(finalJwt);
      }
      log.info(finalJwt);

    } else if (args[0].equals(HS256_VERIFY) && args.length >= 3) {
      Boolean verified = JwtTokenUtils.builder().setSignedJwt(args[1]).setSharedSecret(args[2])
          .build().verifyHs256Jwt();
      log.info("verified: {}", verified);

    } else if (args.length >= 3 && args[0].equals(RS256)) {
      finalJwt = JwtTokenUtils.builder().setProjectId(args[1]).setBase64PrivateKey(args[2]).build()
          .generateSelfSignedJwtForIdToken();

      log.info(finalJwt);

    } else if (args.length >= 4 && args[0].equals(RS256) && args[1].equals(KEY_FILE)) {
      String base64key = readPrivateKey(args[2]);
      base64key = base64key.replace("\n", "");
      log.trace("key:\n{}", base64key);

      finalJwt = JwtTokenUtils.builder().setProjectId(args[3]).setBase64PrivateKey(base64key)
          .setServiceAccount(args[3]).build().generateSelfSignedJwtForIdToken();

      log.info(finalJwt);

    } else if (args.length == 3 && args[0].equals(KEY_FILE)) {
      JwtTokenUtils jwtUtils = new JwtTokenUtils(args[1], args[2]);
      String selfSignedJwt = jwtUtils.generateSelfSignedJwtForIdToken();
      String idToken = jwtUtils.gcpToken(selfSignedJwt);
      log.info("Gcp Identity Token: {}", idToken);

    } else if (args.length == 4 && args[0].equals(ID_TOKEN) && args[1].equals(KEY_FILE)) {
      String base64key = readPrivateKey(args[2]);
      JwtTokenUtils jwtUtils = new JwtTokenUtils(base64key, args[3]);
      String selfSignedJwt = jwtUtils.generateSelfSignedJwtForIdToken();
      String idToken = jwtUtils.gcpToken(selfSignedJwt);
      log.info("Gcp Identity Token: {}", idToken);

    } else if (args.length >= 4 && args[0].equals(ACCESS_TOKEN) && args[1].equals(KEY_FILE)) {
      String base64key = readPrivateKey(args[2]);
      String serviceAccount = args[3];
      JwtTokenUtils jwtUtils = new JwtTokenUtils(base64key, serviceAccount);
      String scope = args.length > 4 ? args[4] : null;
      String selfSignedJwt = jwtUtils.generateSelfSignedJwtForAccessToken(scope);
      String idToken = jwtUtils.gcpToken(selfSignedJwt);
      log.info("Gcp Oauth 2 Access Token: {}", idToken);

    } else {
      printHelp();
    }
  }

  private static void jwtVerbose(String jwt) {
    String[] jwtSplitted = jwt.split("\\.");
    String jwtHeaders = new String(Base64.getDecoder().decode(jwtSplitted[0]));
    String jwtClaims = new String(Base64.getDecoder().decode(jwtSplitted[1]));
    log.info("HEADERS:");
    log.info(jwtHeaders);
    log.info("CLAIMS:");
    log.info(jwtClaims);
  }

  private static void loggingConf() {
    try (InputStream in =
        JwtTokenUtils.class.getClassLoader().getResourceAsStream("logging.properties")) {
      LogManager.getLogManager().readConfiguration(in);
    } catch (IOException e) {
      System.err.printf(e.getMessage());
      System.exit(1);
    }
  }
  

  private static boolean logVerbose(String... params) {
    return checkForParam("-v", params) || checkForParam("--verbose", params);
  }

  private static boolean checkForParam(String toFind, String... params) {
    return Stream.of(params).anyMatch(p -> p.equalsIgnoreCase(toFind));
  }

  private static final String BOLD = "\033[1;37m";
  private static final String RESET = "\033[0m";

  private static void printHelp() {
    StringBuilder sb = new StringBuilder();
    sb.append("\n\n" + BOLD + "JWT UTILS " + RESET + "\n\n");
    sb.append("\033[1;37mUSAGE\033[0m\n");
    sb.append(" -hs256\t\t<shared-secret>\t\tgenerate hs256 jwt\n");
    sb.append(" -hs256verify\t<jwt> <shared-secret>\tverify hs256 jwt\n");
    sb.append(" -rs256\t\t<base64-private-key> <service-account>\n");
    sb.append(" -rs256\t\t -keyFile\t<base64-private-key> <service-account>\n");
    sb.append(" -gcpIdToken\t<base64-private-key> <service-account>\n");
    sb.append(" -gcpIdToken\t-keyFile<base64-private-key> <service-account>\n");
    sb.append(" -accessToken\t-keyFile<base64-private-key> <service-account>\n");
    log.info(sb.toString());
  }

}
