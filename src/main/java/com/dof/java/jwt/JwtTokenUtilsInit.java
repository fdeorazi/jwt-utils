package com.dof.java.jwt;

/**
 *
 * @author fabio.deorazi
 *
 */
public final class JwtTokenUtilsInit {
  private JwtTokenUtilsInit() {}
  /**
   *
   * @return
   */
  public static synchronized JwtTokenUtilsBuilder builder() {
    return new JwtTokenUtilsBuilderDefault();
    
  }
}
