package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;
import com.dof.java.jwt.enums.JwtProps;

class UtilityTest {
  
  @Test
  void loadProperties() {
    String value = JwtProps.GCP_TOKEN_URL.val();
    assertNotNull(value);
    assertThat(value).isNotBlank();
  }
}
