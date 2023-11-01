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

import com.dof.java.jwt.annotation.Cmd;
import com.dof.java.jwt.enums.JwtProps;
import com.dof.java.jwt.enums.TargetTokenType;
import com.dof.java.jwt.exception.JwtTokenUtilsException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Optional;
import java.util.logging.LogManager;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Entry point class to use library from command line.
 * 
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsConsole {
  private static final Logger log = LoggerFactory.getLogger(JwtTokenUtilsConsole.class);

  private String[] cmdArgs;

  public static final int SCREEN_WIDTH = 100;

  private JwtTokenUtilsBuilder builder;

  public JwtTokenUtilsConsole(JwtTokenUtilsBuilder builder) {
    this.builder = builder;
  }

  /**
   * Program available parameters.
   *
   * @author fabio.deorazi
   *
   */
  public enum Parameters {
    HS256("hs256", "hs256", new String[] {"-s"}),
    HS256_VERIFY("hs256-verify", "hs256-verify", new String[] {"-s", "-j"}),
    SSJWT("ssjwt", "ssjwt", new String[] {"-t", "-kf", "-iss"}),
    SSJWT_VERIFY("ssjwt-verify", "ssjwt-verify", new String[] {"-pk", "-j"}),
    ID_TOKEN("idtoken", "idtoken", new String[] {"-kf", "-ta", "-sub", "-iss"}),
    ACCESS_TOKEN("access-token", "access-token", new String[] {"-kf", "-ta", "-scope", "-iss"}),
    TYPE("-t", "--type", new String[] {}),
    SECRET("-s", "--secret", new String[] {}),
    BASE64_KEY("-k", "--key", new String[] {}),
    KEY_FILE("-kf", "--key-file", new String[] {}),
    SERVICE_ACCOUNT("-sa", "--service-account", new String[] {}),
    SIGNED_JWT("-j", "--signed-jwt", new String[] {}),
    TARGET_SERVICE("-ts", "--target-service", new String[] {}),
    VERBOSE("-v", "--verbose", new String[] {}),
    HELP("-h", "--help", new String[] {}),
    PUBLIC_KEY("-pk", "--public-key", new String[] {}),
    ISS("-iss", "--issuer", new String[] {}),
    SUB("-sub", "--subject", new String[] {}),
    SCOPE("-scope", "--scope", new String[] {}),
    AUD("-aud", "--audience", new String[] {}),
    EXP("-exp", "--expire-in", new String[] {}),
    // IAT("-iat", "--issued-at", new String[] {}),
    TARGET_AUDIENCE("-ta", "--target-audience", new String[] {});

    String shortParam;
    String verboseParam;
    String[] params;

    Parameters(String shortParam, String verboseParam, String[] params) {
      this.shortParam = shortParam;
      this.verboseParam = verboseParam;
      this.params = params;
    }

    public boolean isEqual(String value) {
      return this.shortParam.equals(value) || this.verboseParam.equals(value);
    }

    public static Optional<Parameters> get(String id) {
      return Stream.of(Parameters.values()).filter(p -> p.shortParam.contentEquals(id)).findAny();
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


  protected void evalMethod(String... args)
      throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
    cmdArgs = args;

    if (checkForParam(Parameters.HELP)) {
      PrintUtility.printHelp();
      return;
    }

    Iterator<String> iter = Arrays.stream(args).iterator();
    String operation = "";
    while (iter.hasNext()) {
      String param = iter.next();
      if (Parameters.HS256.isEqual(param) || Parameters.HS256_VERIFY.isEqual(param)
          || Parameters.SSJWT.isEqual(param) || Parameters.ID_TOKEN.isEqual(param)
          || Parameters.ACCESS_TOKEN.isEqual(param) || Parameters.SSJWT_VERIFY.isEqual(param)) {
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

      } else if (Parameters.BASE64_KEY.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setBase64privateKey(iter.next());

      } else if (Parameters.KEY_FILE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setKeyFile(iter.next());

      } else if (Parameters.SERVICE_ACCOUNT.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setServiceAccount(iter.next());

      } else if (Parameters.SIGNED_JWT.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setSignedJwt(iter.next());

      } else if (Parameters.SCOPE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setScope(iter.next());

      } else if (Parameters.PUBLIC_KEY.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setPublicKeyFile(iter.next());

      } else if (Parameters.ISS.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setIssuer(iter.next());

      } else if (Parameters.SUB.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setSubject(iter.next());

      } else if (Parameters.AUD.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setAudience(iter.next());

      } else if (Parameters.TARGET_AUDIENCE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setTargetAudience(iter.next());

      } else if (Parameters.TARGET_SERVICE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setTargetServiceUrl(iter.next());

      } else if (Parameters.EXP.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setExpireIn(Integer.valueOf(iter.next()));

      } else if (Parameters.VERBOSE.isEqual(param)) {
        builder.setVerbose(true);
      }

    }

    evalExecution(operation);
  }

  private void evalExecution(String operation)
      throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
    Optional<Method> optional = findMethod(operation);

    if (optional.isPresent()) {
      if (checkForParam(Parameters.VERBOSE)) {
        PrintUtility.logo();
      }

      JwtTokenUtils jwtTokenUtil = builder.build();
      Object result = optional.get().invoke(jwtTokenUtil);

      if (checkForParam(Parameters.VERBOSE)) {
        log.info(String.format("%n%s%s%s", JwtProps.CMD_COLOR1.val(), "Result token",
            JwtProps.CMD_COLOR0.val()));
      }
      System.out.println(result);
    } else {
      throw new JwtTokenUtilsException("Miss command.");
    }
  }

  private static void loggingConf() {
    try (InputStream in = JwtTokenUtilsDefault.class.getClassLoader()
        .getResourceAsStream("console-logging.properties")) {
      LogManager.getLogManager().readConfiguration(in);
    } catch (IOException e) {
      System.err.printf(e.getMessage());
      System.exit(1);
    }
  }

  private boolean checkForParam(Parameters toFind) {
    return Stream.of(cmdArgs).anyMatch(
        p -> (p.equalsIgnoreCase(toFind.shortParam) || p.equalsIgnoreCase(toFind.verboseParam)));
  }

  /**
   * Application entry point.
   *
   * @param args application arguments
   */
  public static void main(String... args) {
    try {
      if (args == null || args.length < 1) {
        log.info("Missed required parameters (2 at least).");
        PrintUtility.printHelp();
        return;
      }

      new JwtTokenUtilsConsole(new JwtTokenUtilsBuilderDefault()).evalMethod(args);

    } catch (Exception e) {
      String errorMessage;
      if (e instanceof InvocationTargetException) {
        errorMessage = ((InvocationTargetException) e).getTargetException().getMessage();
      } else {
        errorMessage = e.getMessage();
      }
      log.error("{}{}: {}{}{}", JwtProps.CMD_COLOR4.val(), "ERROR", JwtProps.CMD_COLOR7.val(),
          errorMessage, JwtProps.CMD_COLOR0.val(), e);
    }
  }

}
