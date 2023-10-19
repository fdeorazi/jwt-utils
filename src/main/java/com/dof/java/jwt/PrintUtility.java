package com.dof.java.jwt;

import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonParser;

public class PrintUtility {
  private static final Logger log = LoggerFactory.getLogger(PrintUtility.class);

  private PrintUtility() {}

  public static synchronized void prettyPrintJwt(String encodedJwt) {
    log.info("{}{}{}{}", JwtProps.CMD_COLOR1.val(), "\nGenerated self signed token ",
        JwtProps.CMD_COLOR0.val(), "(decoded):");
    log.info("{}{}{}", JwtProps.CMD_COLOR2.val(), "Raw Jwt: ", JwtProps.CMD_COLOR0.val());
    log.info("{}", encodedJwt);
    String[] jwtSplitted = encodedJwt.split("\\.");
    String jwtHeaders = new String(Base64.getDecoder().decode(jwtSplitted[0]));
    String jwtClaims = new String(Base64.getDecoder().decode(jwtSplitted[1]));
    prettyPrint(jwtHeaders, "Headers:");
    prettyPrint(jwtClaims, "Claims:");
  }

  private static void prettyPrint(String json, String label) {
    log.info("{}{}{}\n", JwtProps.CMD_COLOR2.val(), label, JwtProps.CMD_COLOR0.val());
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    JsonElement jsonElement = JsonParser.parseString(json);
    log.info("{}\n", gson.toJson(jsonElement));
  }
}
