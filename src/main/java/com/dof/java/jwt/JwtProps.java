package com.dof.java.jwt;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 *
 * @author fabio.deorazi
 *
 */
public enum JwtProps {
  GCP_OAUTH2_SCOPE("gcp.oauth2.scope"), GCP_TOKEN_URL("gcp.token.url");

  String key;

  JwtProps(String key) {
    this.key = key;
  }

  java.util.Properties props;

  void loadProperties() {
    try (InputStream in =
        new FileInputStream(this.getClass().getResource("/application.properties").getPath())) {
      props = new java.util.Properties();
      props.load(in);
    } catch (IOException e) {
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
