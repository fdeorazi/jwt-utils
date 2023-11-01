package com.dof.java.jwt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.text.ParseException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit test.
 *
 * @author fabio.deorazi
 *
 */
class JwtTokenUtilHs256Test implements JwtTokenUtilsTest {

  @Test
  void givenNoParam_whenGenHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateHs256Jwt());
  }

  @Test
  void givenParam_whenGenHs256_thenReturnVerifiedJwt() throws ParseException {
    JwtTokenUtilsBuilder builder =
        JwtTokenUtilsInit.builder().setSharedSecret(TestConstants.SECRET_256_BIT).setVerbose(true);
    String jwt = builder.build().generateHs256Jwt();
    Assertions.assertThat(jwt).isNotBlank();

    assertTrue(assertDoesNotThrow(() -> builder.setSignedJwt(jwt).build().verifyHs256Jwt()));
  }

  @Test
  void givenIncorrectSecret_whenGenHs256_thenThrowException() throws ParseException {
    JwtTokenUtilsBuilder builder = JwtTokenUtilsInit.builder().setSharedSecret("Hello");
    Throwable t =
        assertThrows(IllegalArgumentException.class, () -> builder.build().generateHs256Jwt());
    Assertions.assertThat(t.getMessage()).containsIgnoringCase("at least");
  }

  @Test
  void givenNoParams_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }

  @Test
  void givenNoFirstParam_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().setSignedJwt("test").build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }

  @Test
  void givenNoSecondParam_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().setSharedSecret("test").build();

    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());

  }

  @Test
  void givenWrongJwt_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().setSignedJwt("abc")
        .setSharedSecret(TestConstants.SECRET_256_BIT).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }
}
