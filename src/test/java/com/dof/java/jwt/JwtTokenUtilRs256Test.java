package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.util.Base64;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Test;
import com.jayway.jsonpath.matchers.IsJson;
import com.jayway.jsonpath.matchers.JsonPathMatchers;

/**
 * Class test for RSA / SHA256 jwt creation methods.
 *
 * @author fabio.deorazi
 *
 */
class JwtTokenUtilRs256Test {
  private static final String SERVICE_ACCOUNT = "service-account-test@test.com";
  private static final String TARGET_SERVICE = "http://cloud.service.com/service";

  @Test
  void givenNoParamers_whenGenRs256ForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoServiceAccount_whenGenRs256ForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setTargetServiceUrl(TARGET_SERVICE)
        .setKeyFile("test.pem").setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoTargetService_whenGenRs256ForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setServiceAccount(SERVICE_ACCOUNT)
        .setKeyFile("test.pem").setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenNoBase64KeyNoKeyFile_whenGenRs256ForIdToken_thenThrowException() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setServiceAccount(SERVICE_ACCOUNT)
        .setTargetServiceUrl(TARGET_SERVICE).setTargetTokenType(TargetTokenType.ID_TOKEN).build();
    assertThrows(IllegalArgumentException.class, () -> jwtTokenUtils.generateSelfSignedJwt());
  }

  @Test
  void givenAllParams_whenGenRs256ForIdToken_thenReturnCorrectJwt() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setServiceAccount(SERVICE_ACCOUNT)
        .setTargetServiceUrl(TARGET_SERVICE).setKeyFile("test.pem")
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
  void givenAllParams_whenGenRs256ForAccessToken_thenReturnCorrectJwt() {
    JwtTokenUtils jwtTokenUtils = JwtTokenUtils.builder().setServiceAccount(SERVICE_ACCOUNT)
        .setTargetServiceUrl(TARGET_SERVICE).setKeyFile("test.pem")
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
}
