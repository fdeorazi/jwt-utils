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

import com.dof.java.jwt.JwtTokenUtilsConsole.Parameters;
import com.dof.java.jwt.enums.JwtProps;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility print text class.
 *
 * @author fabio.deorazi
 *
 */
public class PrintUtility {
  private static final Logger log = LoggerFactory.getLogger(PrintUtility.class);
  private static int menuWidth;

  static {
    menuWidth = Integer.valueOf(JwtProps.CMD_MENU_WIDTH.val());
  }

  private PrintUtility() {}

  /**
   * Print the Base64 JWT (not opaque) formatted.
   *
   * @param encodedJwt self signed JWT.
   */
  public static synchronized void indentJwt(String encodedJwt, String label) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.format("%s%s%s%s%n", JwtProps.CMD_COLOR1.val(), label, "(decoded):",
        JwtProps.CMD_COLOR0.val()));

    String[] jwtSplitted = encodedJwt.split("\\.");
    String jwtHeaders = new String(Base64.getDecoder().decode(jwtSplitted[0]));
    String jwtClaims = new String(Base64.getDecoder().decode(jwtSplitted[1]));
    sb.append(indentJson(jwtHeaders, "Headers "));
    sb.append(indentJson(jwtClaims, "Claim"));
    log.info("{}", sb);
  }

  private static String indentJson(String json, String label) {
    StringBuilder sb = new StringBuilder();
    sb.append(
        String.format("%s%s%s%n", JwtProps.CMD_COLOR5.val(), label, JwtProps.CMD_COLOR0.val()));

    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonElement jsonElement = JsonParser.parseString(json);
    String prettyJson = gson.toJson(jsonElement);
    sb.append(String.format("%s%s%s%n", JwtProps.CMD_COLOR3.val(), prettyJson,
        JwtProps.CMD_COLOR0.val()));

    return sb.toString();
  }

  /**
   * Format text based on left space and console width.
   *
   * @param sb string builder on with insert the formatted text
   * @param s the string to format
   * @param format the left space
   * @param screenWidth max line width
   */
  public static void format(StringBuilder sb, String s, int format, int screenWidth) {
    int textPos = 0;
    sb.append("\n");

    while (textPos < s.length()) {
      int textLeft = s.length() - textPos;
      int screenLeft = screenWidth - format;
      int nlPos = s.indexOf("/n", textPos) - textPos;
      int lineLength = 0;
      if (nlPos > -1 && nlPos < textLeft && nlPos < screenWidth) {
        lineLength = nlPos;
      } else {
        lineLength = textLeft < screenLeft ? textLeft : screenLeft;
      }

      String line = s.substring(textPos, textPos + lineLength);
      String formattedLine = String.format("%s%s%n", " ".repeat(format), line);

      sb.append(formattedLine);

      textPos += lineLength;
      if (nlPos != -1) {
        textPos += 2;
      }
    }
  }

  /**
   * Prints application logo.
   */
  public static void logo() {
    StringBuilder sb = new StringBuilder();
    logo(sb);
    log.info("{}", sb);
  }

  /**
   * Creates application logo and append it to a {@link StringBuilder}.
   *
   * @param sb the {@link StringBuilder} on which append application logo.
   */
  public static void logo(StringBuilder sb) {
    sb.append(String.format("%s%s", JwtProps.CMD_COLOR1.val(), "_".repeat(menuWidth)));
    sb.append(JwtProps.CMD_TITLE.val());
    sb.append(String.format("%s%s%s%n", JwtProps.CMD_BGCOLOR1.val(), " ".repeat(menuWidth),
        JwtProps.CMD_COLOR0.val()));
  }

  /**
   * Prints Help menu.
   * 
   */
  public static void printHelp() {
    StringBuilder sb = new StringBuilder();

    logo(sb);

    sb.append(String.format("%n%s%s%s%n", JwtProps.CMD_COLOR1.val(), JwtProps.CMD_LABEL1.val(),
        JwtProps.CMD_COLOR0.val()));

    sb.append(String.format("%4c%s%-15s%n%n", 32, JwtProps.CMD_COLOR3.val(),
        JwtProps.CMD_HELP_USAGE.val()));

    // command header
    sb.append(String.format("%s%s%s%n", JwtProps.CMD_COLOR1.val(), JwtProps.CMD_LABEL2.val(),
        JwtProps.CMD_COLOR0.val()));

    // commands

    Stream.of(Parameters.values()).filter(p -> !p.shortParam.startsWith("-")).forEach(p -> {

      // command name

      sb.append(String.format("%4c%s%-11s%s", 32, JwtProps.CMD_COLOR5.val(), p.shortParam,
          JwtProps.CMD_COLOR0.val()));

      // command description

      JwtProps jwtc = null;
      try {
        jwtc = JwtProps.valueOf("CMD_" + (p.toString()));
      } catch (Exception e) {
      }
      sb.append(JwtProps.CMD_COLOR3.val());
      PrintUtility.format(sb, jwtc != null ? jwtc.val() : "", 8, menuWidth);

      // required flags

      StringBuilder psb = new StringBuilder("Required Flags: ");
      Arrays.stream(p.params).forEach(pnum -> {
        Optional<Parameters> param = Parameters.get(pnum);
        psb.append(String.format("%s ", param.get().shortParam));
      });

      sb.append(String.format("%8c%-20s%n", 32, psb.toString()));
      sb.append(JwtProps.CMD_COLOR0.val());
    });

    // flags

    sb.append(String.format("%n%s%s%s%n", JwtProps.CMD_COLOR1.val(), JwtProps.CMD_LABEL3.val(),
        JwtProps.CMD_COLOR0.val()));
    Stream.of(Parameters.values()).filter(p -> p.shortParam.startsWith("-"))
        .sorted((o1, o2) -> o1.shortParam.charAt(1) < o2.shortParam.charAt(1) ? -1 : 1)
        .forEach(p -> {

          JwtProps jwtp = null;
          
          jwtp = JwtProps.valueOf("CMD_FLAGS_" + (p.toString()));

          sb.append(String.format("%4c%s%s, %-19s%s", 32, JwtProps.CMD_COLOR5.val(), p.shortParam,
              p.verboseParam, JwtProps.CMD_COLOR0.val()));
          sb.append(JwtProps.CMD_COLOR3.val());
          PrintUtility.format(sb, jwtp != null ? jwtp.val() : "", 8, menuWidth);
          sb.append(JwtProps.CMD_COLOR0.val());
        });

    // examples
    sb.append(String.format("%n%s%s%s", JwtProps.CMD_COLOR1.val(), "Examples",
        JwtProps.CMD_COLOR0.val()));
    sb.append(JwtProps.CMD_COLOR3.val());
    PrintUtility.format(sb, JwtProps.CMD_EXAMPLE1_DESC.val(), 4, menuWidth);
    sb.append(JwtProps.CMD_COLOR3.val());
    PrintUtility.format(sb, JwtProps.CMD_EXAMPLE1.val(), 6, menuWidth);

    PrintUtility.format(sb, JwtProps.CMD_EXAMPLE2_DESC.val(), 4, menuWidth);
    sb.append(JwtProps.CMD_COLOR3.val());
    PrintUtility.format(sb, JwtProps.CMD_EXAMPLE2.val(), 6, menuWidth);
    sb.append(JwtProps.CMD_COLOR0.val());

    log.info("{}", sb);
  }
}
