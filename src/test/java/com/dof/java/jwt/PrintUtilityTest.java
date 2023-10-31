package com.dof.java.jwt;

import org.junit.jupiter.api.Test;

/**
 * 
 */
public class PrintUtilityTest {

  @Test
  void printFormatted() {
    StringBuilder sb = new StringBuilder();
    String text = "java -jar jwt-utils.jar hs256 \\/n"
        + "  -s $(echo secret... | sha256sum) > jwt.txt/n/n"
        + "java -jar jwt-utils.jar hs256-verify \\/n"
        + "  -s $(echo secret... | sha256sum) \\/n"
        + "  -j $(cat jwt.txt)";
    PrintUtility.format(sb, text, 6, 50);
    System.out.println(sb.toString());
  }
}
