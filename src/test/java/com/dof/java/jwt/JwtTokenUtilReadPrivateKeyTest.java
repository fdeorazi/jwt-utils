package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.Test;

class JwtTokenUtilReadPrivateKeyTest {

  @Test
  void givenFileName_whenRead_returnBase64Key() throws IOException {
    URL url = this.getClass().getClassLoader().getResource("pk2048.pem");
    String filePath = url.getPath();
    String b64Key = JwtTokenUtilsInit.builder().build().readPrivateKey(filePath);
    assertThat(b64Key).doesNotContain(System.lineSeparator());
  }
}
