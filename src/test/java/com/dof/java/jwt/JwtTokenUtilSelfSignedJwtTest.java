package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import com.dof.java.jwt.enums.TargetTokenType;
import com.dof.java.jwt.exception.RequestTokenHttpException;
import com.jayway.jsonpath.matchers.JsonPathMatchers;

/**
 * Class test for RSA / SHA256 jwt creation methods.
 *
 * @author fabio.deorazi
 *
 */
class JwtTokenUtilSelfSignedJwtTest implements JwtTokenUtilsTest {

  @Test
  void givenNoParamers_whenSsJwtForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoServiceAccount_whenSsJwtForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder()
        .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
        .setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoTargetTokenType_whenSsJwtForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
            .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
            .build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoTargetService_whenSsJwtForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder()
        .setServiceAccount(TestConstants.SERVICE_ACCOUNT).setKeyFile(TestConstants.KEY_FILE)
        .setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoBase64KeyNoKeyFile_whenSsJwtForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
            .setTargetServiceUrl(TestConstants.TARGET_SERVICE)
            .setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenAllParams_whenSsJwtForIdToken_thenReturnCorrectJwt() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
            .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
            .setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    String jwt = assertDoesNotThrow(() -> jwtTokenUtils.generateSelfSignedJwt());
    assertThat(jwt).isNotBlank();
    String[] splittedJwt = jwt.split("\\.");
    assertThat(splittedJwt).hasSize(3);
    String headers = new String(Base64.getDecoder().decode(splittedJwt[0]));
    String claims = new String(Base64.getDecoder().decode(splittedJwt[1]));

    MatcherAssert.assertThat(headers, JsonPathMatchers.isJson());
    MatcherAssert.assertThat(claims, JsonPathMatchers.isJson());
  }

  @Test
  void givenAllParams_whenSsJwtForAccessToken_thenReturnCorrectJwt() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
            .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
            .setTargetTokenType(TargetTokenType.ACCESS_TOKEN).build();
    String jwt = assertDoesNotThrow(() -> jwtTokenUtils.generateSelfSignedJwt());
    assertThat(jwt).isNotBlank();
    String[] splittedJwt = jwt.split("\\.");
    assertThat(splittedJwt).hasSize(3);
    String headers = new String(Base64.getDecoder().decode(splittedJwt[0]));
    String claims = new String(Base64.getDecoder().decode(splittedJwt[1]));

    MatcherAssert.assertThat(headers, JsonPathMatchers.isJson());
    MatcherAssert.assertThat(claims, JsonPathMatchers.isJson());
  }

  @Test
  void givenSignedJwt_whenVerify_theReturnVerified()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    String ssjwt = JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
        .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE_2048)
        .setTargetTokenType(TargetTokenType.ACCESS_TOKEN).setVerbose(true).build()
        .generateSelfSignedJwt();

    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setPublicKeyFile(TestConstants.PUB_KEY_FILE_2048)
            .setSignedJwt(ssjwt).setVerbose(true).build();
    assertTrue(assertDoesNotThrow(() -> jwtTokenUtils.verifyRs256Jwt()));

  }

  @Test
  void givenInvalidSignedJwt_whenVerify_theThrowException()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    String ssjwt = JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
        .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
        .setTargetTokenType(TargetTokenType.ACCESS_TOKEN).build().generateSelfSignedJwt();
    ssjwt = ssjwt.replace(".", ",");

    JwtTokenUtils jwtTokenUtils = JwtTokenUtilsInit.builder()
        .setPublicKeyFile(TestConstants.PUB_KEY_FILE).setSignedJwt(ssjwt).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.verifyRs256Jwt());

  }

  @Test
  void givenAllParams_whenGenToken_thenReturnCorrectJwt() {
    JwtTokenUtils jwtTokenUtils =
        JwtTokenUtilsInit.builder().setServiceAccount(TestConstants.SERVICE_ACCOUNT)
            .setTargetServiceUrl(TestConstants.TARGET_SERVICE).setKeyFile(TestConstants.KEY_FILE)
            .setTargetTokenType(TargetTokenType.ID_TOKEN).setVerbose(true).build();
    assertThrows(RequestTokenHttpException.class, () -> jwtTokenUtils.generateToken());

  }
}
