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
    HS256("hs256", "hs256", 1, new int[] {7}),
    HS256_VERIFY("hs256-verify", "hs256-verify", 2, new int[] {7, 12}),
    SSJWT("ssjwt", "ssjwt", 3, new int[] {6, 9, 10, 13, 11}),
    ID_TOKEN("idtoken", "idtoken", 4, new int[] {9, 10, 13, 11}),
    ACCESS_TOKEN("access-token", "access-token", 5, new int[] {9, 10, 13, 11}),
    TYPE("-t", "--type", 6, new int[] {}),
    SECRET("-s", "--secret", 7, new int[] {}),
    PROJECT_ID("-p", "--project-id", 8, new int[] {}),
    BASE64_KEY("-k", "--key", 9, new int[] {}),
    KEY_FILE("-kf", "--key-file", 10, new int[] {}),
    SERVICE_ACCOUNT("-sa", "--service-account", 11, new int[] {}),
    SIGNED_JWT("-j", "--signed-jwt", 12, new int[] {}),
    TARGET_SERVICE("-ts", "--target-service", 13, new int[] {}),
    VERBOSE("-v", "--verbose", 14, new int[] {}),
    HELP("-h", "--help", 15, new int[] {}),
    PUBLIC_KEY("-pk", "--public-key", 16, new int[] {}),
    SSJWT_VERIFY("ssjwt-verify", "ssjwt-verify", 17, new int[] {16, 12}),
    SCOPE("-sc", "--scope", 18, new int[] {});

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

      } else if (Parameters.SCOPE.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setScope(iter.next());

      } else if (Parameters.PUBLIC_KEY.isEqual(param)) {
        Assert.hasNext(iter);
        builder.setPublicKeyFile(iter.next());

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
    try (InputStream in =
        JwtTokenUtilsDefault.class.getClassLoader().getResourceAsStream("logging.properties")) {
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
      log.error("{}{}{}", JwtProps.CMD_COLOR4.val(), "ERROR", JwtProps.CMD_COLOR0.val());
      log.error(errorMessage, e);
    }
  }

}
