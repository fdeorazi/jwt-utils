package com.dof.java.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Optional;
import java.util.logging.LogManager;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.util.ArrayIterator;
import com.nimbusds.jose.JOSEException;

/**
 * Entry point class to use library from command line.
 * 
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsConsole {
  private static final Logger log = LoggerFactory.getLogger(JwtTokenUtilsConsole.class);

  /**
   * Program available parameters.
   *
   * @author fabio.deorazi
   *
   */
  public enum Parameters {
    RS256("rs256", "rs256"), ID_TOKEN("idtoken", "idtoken"), ACCESS_TOKEN("access-token",
        "access-token"), HS256("hs256", "hs256"), HS256_VERIFY("hs256-verify",
            "hs256-verify"), SECRET("-s", "--secret"), PROJECT_ID("-p", "--project-id"), BASE64_KEY(
                "-k",
                "--key"), KEY_FILE("-kf", "--key-file"), SERVICE_ACCOUNT("-s", "--service-account");

    String shortParam;
    String verboseParam;
    String methodName;

    Parameters(String shortParam, String verboseParam) {
      this.shortParam = shortParam;
      this.verboseParam = verboseParam;
    }

    public boolean isEqual(String value) {
      return this.shortParam.equals(value) || this.verboseParam.equals(value);
    }
  }


  // LOGGING CONFIG
  static {
    loggingConf();
  }

  private static Optional<Method> findMethod(String operation) {
    return Stream.of(JwtTokenUtils.class.getDeclaredMethods())
        .filter(m -> m.isAnnotationPresent(Cmd.class)
            && m.getAnnotation(Cmd.class).param().equals(operation))
        .findFirst();
  }

  private static void evalMethod(String... args)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException,
      JOSEException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
    String finalJwt;

    JwtTokenUtilsBuilder builder = JwtTokenUtils.builder();

    Iterator<String> iter = new ArrayIterator<>(args);
    String operation = "";
    while (iter.hasNext()) {
      String nextParam = iter.next();
      if (Parameters.HS256.isEqual(nextParam) || Parameters.HS256_VERIFY.isEqual(nextParam)
          || Parameters.RS256.isEqual(nextParam) || Parameters.ACCESS_TOKEN.isEqual(nextParam)
          || Parameters.ID_TOKEN.isEqual(nextParam)) {
        operation = nextParam;
        if (Parameters.ID_TOKEN.isEqual(nextParam)) {
          builder.setTargetTokenType(TargetTokenType.ID_TOKEN);
        } else if (Parameters.ACCESS_TOKEN.isEqual(nextParam)) {
          builder.setTargetTokenType(TargetTokenType.ACCESS_TOKEN);
        }
      } else if (Parameters.SECRET.isEqual(nextParam)) {
        Assert.hasNext(iter);
        builder.setSharedSecret(iter.next());

      } else if (Parameters.PROJECT_ID.isEqual(nextParam)) {
        Assert.hasNext(iter);
        builder.setProjectId(iter.next());

      } else if (Parameters.BASE64_KEY.isEqual(nextParam)) {
        Assert.hasNext(iter);
        builder.setBase64PrivateKey(iter.next());

      } else if (Parameters.KEY_FILE.isEqual(nextParam)) {
        builder.setKeyFile(iter.next());

      } else if (Parameters.SERVICE_ACCOUNT.isEqual(nextParam)) {
        builder.setServiceAccount(iter.next());
      }
    }

    Optional<Method> optional = findMethod(operation);

    if (optional.isPresent()) {
      // optional.get().getReturnType()
      Object result = optional.get().invoke(builder.build());
      log.info((String) result);
    } else {
      throw new RuntimeException("Miss method");
    }

    /*
     * if (args.length >= 2 && args[0].equals(HS256) && args[1] != null) { finalJwt =
     * JwtTokenUtils.builder().setSharedSecret(args[1]).build().generateHs256Jwt(); if
     * (logVerbose(args)) { jwtVerbose(finalJwt); } log.info(finalJwt);
     * 
     * } else if (args[0].equals(HS256_VERIFY) && args.length >= 3) { Boolean verified =
     * JwtTokenUtils.builder().setSignedJwt(args[1]).setSharedSecret(args[2])
     * .build().verifyHs256Jwt(); log.info("verified: {}", verified);
     * 
     * } else if (args.length >= 3 && args[0].equals(RS256)) { finalJwt =
     * JwtTokenUtils.builder().setProjectId(args[1]).setBase64PrivateKey(args[2]).build()
     * .generateSelfSignedJwtForIdToken();
     * 
     * log.info(finalJwt);
     * 
     * } else if (args.length >= 4 && args[0].equals(RS256) && args[1].equals(KEY_FILE)) { String
     * base64key = readPrivateKey(args[2]); base64key = base64key.replace("\n", "");
     * log.trace("key:\n{}", base64key);
     * 
     * finalJwt = JwtTokenUtils.builder().setProjectId(args[3]).setBase64PrivateKey(base64key)
     * .setServiceAccount(args[3]).build().generateSelfSignedJwtForIdToken();
     * 
     * log.info(finalJwt);*
     * 
     * } else if (args.length == 3 && args[0].equals(KEY_FILE)) { JwtTokenUtils jwtUtils = new
     * JwtTokenUtils(args[1], args[2]); String selfSignedJwt =
     * jwtUtils.generateSelfSignedJwtForIdToken(); String idToken =
     * jwtUtils.gcpToken(selfSignedJwt); log.info("Gcp Identity Token: {}", idToken);
     * 
     * } else if (args.length == 4 && args[0].equals(ID_TOKEN) && args[1].equals(KEY_FILE)) { String
     * base64key = readPrivateKey(args[2]); JwtTokenUtils jwtUtils = new JwtTokenUtils(base64key,
     * args[3]); String selfSignedJwt = jwtUtils.generateSelfSignedJwtForIdToken(); String idToken =
     * jwtUtils.gcpToken(selfSignedJwt); log.info("Gcp Identity Token: {}", idToken);
     * 
     * } else if (args.length >= 4 && args[0].equals(ACCESS_TOKEN) && args[1].equals(KEY_FILE)) {
     * String base64key = readPrivateKey(args[2]); String serviceAccount = args[3]; JwtTokenUtils
     * jwtUtils = new JwtTokenUtils(base64key, serviceAccount); String scope = args.length > 4 ?
     * args[4] : null; String selfSignedJwt = jwtUtils.generateSelfSignedJwtForAccessToken(scope);
     * String idToken = jwtUtils.gcpToken(selfSignedJwt); log.info("Gcp Oauth 2 Access Token: {}",
     * idToken);
     * 
     * } else { printHelp(); }
     */
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

  /**
   * Application entry point.
   *
   * @param args application arguments
   */
  public static void main(String[] args) {
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

}
