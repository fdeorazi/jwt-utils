package com.dof.java.jwt;

import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

/**
 *
 * @author fabio.deorazi
 *
 */
class JwtTokenUtilTest {

  @Test
  void requiredArguments() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().build();
    assertThrows(IllegalArgumentException.class,
        () -> jwtTokenUtils.generateHs256Jwt());
  }
}
