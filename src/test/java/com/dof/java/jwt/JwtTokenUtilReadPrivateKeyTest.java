package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import org.junit.jupiter.api.Test;

class JwtTokenUtilReadPrivateKeyTest {

  @Test
  void givenFileName_whenRead_returnBase64Key() throws IOException {
    String b64Key = JwtTokenUtils.builder().build().readPrivateKey("test.pem");
    assertThat(b64Key).doesNotContain(System.lineSeparator());
  }
}
