package com.dof.java.jwt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.text.ParseException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JOSEException;

/**
 * Unit test.
 *
 * @author fabio.deorazi
 *
 */
class JwtTokenUtilHs256Test {

  @Test
  void givenNoParam_whenGenHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateHs256Jwt());
  }

  @Test
  void givenParam_whenGenHs256_thenReturnCorrectJwt() throws ParseException, JOSEException {
    JwtTokenUtilsBuilder builder = JwtTokenUtils.builder().setSharedSecret(TestConstants.SECRET_256_BIT);
    String jwt = builder.build().generateHs256Jwt();
    Assertions.assertThat(jwt).isNotBlank();

    assertTrue(assertDoesNotThrow(() -> builder.setSignedJwt(jwt).build().verifyHs256Jwt()));
  }

  @Test
  void givenIncorrectSecret_whenGenHs256_thenThrowException() throws ParseException, JOSEException {
    JwtTokenUtilsBuilder builder = JwtTokenUtils.builder().setSharedSecret("Hello");
    Throwable t =
        assertThrows(IllegalArgumentException.class, () -> builder.build().generateHs256Jwt());
    Assertions.assertThat(t.getMessage()).containsIgnoringCase("at least");
  }

  @Test
  void givenNoParams_whenVerifyHs256_thenThrowException() {


    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }

  @Test
  void givenNoFirstParam_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setSignedJwt("test").build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }

  @Test
  void givenNoSecondParam_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setSharedSecret("test").build();

    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());

  }

  @Test
  void givenWrongJwt_whenVerifyHs256_thenThrowException() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtils.builder().setSignedJwt("abc").setSharedSecret(TestConstants.SECRET_256_BIT).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyHs256Jwt());
  }
}
