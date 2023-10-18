package com.dof.java.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.Optional;
import java.util.logging.LogManager;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.util.ArrayIterator;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonParser;

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
    HS256("hs256", "hs256", 1, new int[] {7}), HS256_VERIFY("hs256-verify", "hs256-verify", 2,
        new int[] {7, 12}), SSJWT("ssjwt", "ssjwt", 3, new int[] {6, 9, 10, 13, 11}), ID_TOKEN(
            "idtoken", "idtoken", 4, new int[] {9, 10, 13, 11}), ACCESS_TOKEN("access-token",
                "access-token", 5,
                new int[] {9, 10, 13, 11}), TYPE("-t", "--type", 6, new int[] {}), SECRET("-s",
                    "--secret", 7, new int[] {}), PROJECT_ID("-p", "--project-id", 8,
                        new int[] {}), BASE64_KEY("-k", "--key", 9, new int[] {}), KEY_FILE("-kf",
                            "--key-file", 10, new int[] {}), SERVICE_ACCOUNT("-sa",
                                "--service-account", 11, new int[] {}), SIGNED_JWT("-j",
                                    "--signed-jwt", 12, new int[] {}), TARGET_SERVICE("-ts",
                                        "--target-service", 13, new int[] {});

    String shortParam;
    String verboseParam;
    int id;
    int[] params;

    Parameters(String shortParam, String verboseParam, int id, int[] params) {
      this.shortParam = shortParam;
      this.verboseParam = verboseParam;
      this.id = id;
      this.params = params;
    }

    public boolean isEqual(String value) {
      return this.shortParam.equals(value) || this.verboseParam.equals(value);
    }

    public static Optional<Parameters> get(int id) {
      return Stream.of(Parameters.values()).filter(p -> p.id == id).findAny();
    }
  }


  // LOGGING CONFIG
  static {
    loggingConf();
  }

  private static Optional<Method> findMethod(String operation) {
    return Stream.of(JwtTokenUtils.class.getDeclaredMethods())
        .filter(m -> m.isAnnotationPresent(Cmd.class) && Stream
            .of(m.getAnnotation(Cmd.class).param()).anyMatch(p -> p.equalsIgnoreCase(operation)))
        .findFirst();
  }

  private void evalMethod(String... args)
      throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {

    JwtTokenUtilsBuilder builder = JwtTokenUtils.builder();

    Iterator<String> iter = new ArrayIterator<>(args);
    String operation = "";
    while (iter.hasNext()) {
      String param = iter.next();
      if (Parameters.HS256.isEqual(param) || Parameters.HS256_VERIFY.isEqual(param)
          || Parameters.SSJWT.isEqual(param) || Parameters.ID_TOKEN.isEqual(param)
          || Parameters.ACCESS_TOKEN.isEqual(param)) {
        operation = param;
        if (Parameters.ID_TOKEN.isEqual(param)) {
          builder.setTargetTokenType(TargetTokenType.ID_TOKEN);
        }
        if (Parameters.ACCESS_TOKEN.isEqual(param)) {
          builder.setTargetTokenType(TargetTokenType.ACCESS_TOKEN);
        }
      } else if (Parameters.TYPE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setTargetTokenType(TargetTokenType.get(iter.next()));

      } else if (Parameters.SECRET.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setSharedSecret(iter.next());

      } else if (Parameters.PROJECT_ID.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setProjectId(iter.next());

      } else if (Parameters.BASE64_KEY.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setBase64PrivateKey(iter.next());

      } else if (Parameters.KEY_FILE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setKeyFile(iter.next());

      } else if (Parameters.SERVICE_ACCOUNT.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setServiceAccount(iter.next());

      } else if (Parameters.SIGNED_JWT.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setSignedJwt(iter.next());

      } else if (Parameters.TARGET_SERVICE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setTargetServiceUrl(iter.next());
      }
    }

    Optional<Method> optional = findMethod(operation);

    if (optional.isPresent()) {
      // optional.get().getReturnType()
      Object result = optional.get().invoke(builder.build());
      if (result instanceof String && !Parameters.HS256_VERIFY.isEqual(operation)) {
        printVerbose((String) result, args);
      }
      log.info((String) result);
    } else {
      throw new RuntimeException("Miss method");
    }
  }

  private void printVerbose(String jwt, String... params) {
    if (checkForParam("-v", params) || checkForParam("--verbose", params)) {

      String[] jwtSplitted = jwt.split("\\.");
      String jwtHeaders = new String(Base64.getDecoder().decode(jwtSplitted[0]));
      String jwtClaims = new String(Base64.getDecoder().decode(jwtSplitted[1]));
      log.info("HEADERS:");
      log.info(prettyPrint(jwtHeaders));
      log.info("CLAIMS:");
      log.info(prettyPrint(jwtClaims));
    }
  }

  String prettyPrint(String json) {
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonElement jsonElement = JsonParser.parseString(json);
    return gson.toJson(jsonElement);
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


  private static boolean checkForParam(String toFind, String... params) {
    return Stream.of(params).anyMatch(p -> p.equalsIgnoreCase(toFind));
  }

  private static final String BOLD = "\033[1;37m";
  private static final String RESET = "\033[0m";

  private static void printHelp() {
    StringBuilder sb = new StringBuilder();
    sb.append("\n\n" + BOLD + "JWT UTILS " + RESET + "\n\n");
    sb.append("\033[1;37mUSAGE:\033[0m\n");
    sb.append(String.format("\t%-15s", JwtProps.CMD_HELP_USAGE.val()));

    sb.append("\n\033[1;37mFUNCTIONS:\033[0m\n");
    Stream.of(Parameters.values()).filter(p -> !p.shortParam.startsWith("-")).forEach(p -> {
      sb.append(String.format("\t%-15s", p.shortParam));
      Arrays.stream(p.params).forEach(pnum -> {
        Optional<Parameters> param = Parameters.get(pnum);
        sb.append(String.format("%-3s", param.get().shortParam)).append("  ");
      });
      sb.append("\n");
    });

    sb.append("\n\033[1;37mPARAMETERS:\033[0m\n");
    Stream.of(Parameters.values()).filter(p -> p.shortParam.startsWith("-")).forEach(p -> {
      String description = "";
      JwtProps jwtp = null;
      try {
        jwtp = JwtProps.valueOf("CMD_FLAGS_" + (p.toString()));
        log.info(jwtp.val());
      } catch (Exception e) {
      }

      sb.append(String.format("\t%-3s, %-15s", p.shortParam, p.verboseParam)).append("\t")
          .append(jwtp != null ? jwtp.val() : "").append("\n");
    });

    /*
     * sb.append(" hs256\t\t-s|--secret\t\t\tgenerate hs256 jwt\n");
     * sb.append(" hs256verify\t-j|--signed-jwt\t\tverify hs256 jwt\n"); sb.append(
     * " ssjwt\t\t-t|--type [idtoken|access-token]  -k|--key|-kf|--key-file  -ts|--target-service  -sa|--service-account\n"
     * ); sb.append(" idtoken\t-k|--key  -sa|--service-account\n");
     * sb.append(" access-token\t-k|--key  -sa|--service-account\n");
     */
    log.info(sb.toString());
  }

  /**
   * Application entry point.
   *
   * @param args application arguments
   */
  public static void main(String[] args) {
    try {
      if (args == null || args.length < 1) {
        log.info("Missed required parameters (2 at least).");
        printHelp();
        return;
      }

      if (args[args.length - 1].equalsIgnoreCase("-help")) {
        printHelp();
        return;
      }


      log.debug("Passed arguments: {}", args.length);
      Arrays.stream(args).forEach(arg -> {
        log.debug("{}\n", arg);
      });

      new JwtTokenUtilsConsole().evalMethod(args);

    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }
  }

}
