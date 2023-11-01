package com.dof.java.jwt;

/**
 * Utility class get the implementation of interfaces.
 * 
 *
 */
public final class JwtTokenUtilsInit {
  private JwtTokenUtilsInit() {}

  /**
   * Return a new {@link JwtTokenUtilsBuilder} instance that is the entry point to parameterize
   * and create self signed JWT, OpenID and Access Tokens.
   *
   */
  public static synchronized JwtTokenUtilsBuilder builder() {
    return new JwtTokenUtilsBuilderDefault();

  }
}
