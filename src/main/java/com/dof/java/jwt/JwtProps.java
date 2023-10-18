package com.dof.java.jwt;

import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author fabio.deorazi
 *
 */
public enum JwtProps {
  GCP_OAUTH2_SCOPE("gcp.oauth2.scope"), GCP_TOKEN_URL("gcp.token.url"), CMD_HELP_USAGE(
      "cmd.help.usage"), CMD_FLAGS_TYPE("cmd.flags.type"), CMD_FLAGS_SECRET(
          "cmd.flags.secret"), CMD_FLAGS_PROJECT_ID("cmd.flags.type"), CMD_FLAGS_BASE64_KEY(
              "cmd.flags.key"), CMD_FLAGS_KEY_FILE("cmd.flags.key.file"), CMD_FLAGS_SERVICE_ACCOUNT(
                  "cmd.flags.service.account"), CMD_FLAGS_SIGNED_JWT(
                      "cmd.flags.signed.jwt"), CMD_FLAGS_TARGET_SERVICE(
                          "cmd.flags.target.service"), CMD_FLAGS_VERBOSE("cmd.flags.verbose");

  String key;

  JwtProps(String key) {
    this.key = key;
  }

  java.util.Properties props;

  void loadProperties() {
    try (InputStream in = this.getClass().getResourceAsStream("/application.properties")) {
      props = new java.util.Properties();
      props.load(in);
    } catch (IOException e) {
      e.printStackTrace();
      throw new RuntimeException("Properies file not found.");
    }
  }

  /**
   *
   * @param prop
   * @return
   */
  public String val() {
    if (props == null) {
      loadProperties();
    }
    return (String) props.get(this.key);
  }
}
