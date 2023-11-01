package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

/**
 * Test to check if text i
 * 
 */
class PrintUtilityTest {

  @Test
  void givenText_whenFormat_printFormatted() {
    StringBuilder sb = new StringBuilder();
    String text = "java -jar jwt-utils.jar hs256 \\/n"
        + "  -s $(echo secret... | sha256sum) > jwt.txt/n/n"
        + "java -jar jwt-utils.jar hs256-verify \\/n"
        + "  -s $(echo secret... | sha256sum) \\/n"
        + "  -j $(cat jwt.txt)";
    PrintUtility.format(sb, text, 6, 50);
    System.out.println(sb.toString());
    assertThat(sb).isNotBlank();
  }
}
