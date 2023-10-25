package com.dof.java.jwt;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.LogManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public interface JwtTokenUtilsTest {

  @BeforeAll
  default void loggingConf() {
    try (InputStream in =
        JwtTokenUtilsDefault.class.getClassLoader().getResourceAsStream("logging.properties")) {
      LogManager.getLogManager().readConfiguration(in);
    } catch (IOException e) {
      System.err.printf(e.getMessage());
      System.exit(1);
    }
  }
}
