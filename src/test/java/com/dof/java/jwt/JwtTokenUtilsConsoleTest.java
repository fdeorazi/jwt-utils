package com.dof.java.jwt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.net.URL;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.JwtTokenUtilsConsole.Parameters;
import com.dof.java.jwt.enums.TargetTokenType;

/**
 * Test the entry point class when use from console.
 * 
 */
class JwtTokenUtilsConsoleTest implements JwtTokenUtilsTest {
  Logger log = LoggerFactory.getLogger(JwtTokenUtilsConsoleTest.class);

  ByteArrayOutputStream outCaptor = new ByteArrayOutputStream();
  ByteArrayOutputStream errCaptor = new ByteArrayOutputStream();

  @BeforeEach
  void setup() {
    loggingConf();
    System.setOut(new PrintStream(outCaptor));
    System.setErr(new PrintStream(errCaptor));
  }

  @AfterAll
  static void reset() {
    System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
    System.setErr(new PrintStream(new FileOutputStream(FileDescriptor.err)));
  }


  @Test
  void givenParams_whenHs256_printJwt() {
    JwtTokenUtilsConsole.main(Parameters.HS256.shortParam, Parameters.SECRET.shortParam,
        TestConstants.SECRET_256_BIT);

    log.debug(outCaptor.toString());
    assertNotNull(outCaptor.toString());
  }

  @Test
  void givenParams_whenHs256Verify_printJwt() {
    JwtTokenUtilsConsole.main(Parameters.HS256.shortParam, Parameters.SECRET.shortParam,
        TestConstants.SECRET_256_BIT);

    Assertions.assertThat(outCaptor.toString()).isNotBlank();
    String ssjwt = outCaptor.toString();

    JwtTokenUtilsConsole.main(Parameters.HS256_VERIFY.shortParam, Parameters.SECRET.shortParam,
        TestConstants.SECRET_256_BIT, Parameters.SIGNED_JWT.verboseParam, ssjwt);
  }

  @Test
  void givenMissParam_whenHs256_printError() {
    JwtTokenUtilsConsole.main(Parameters.HS256.shortParam);

    Assertions.assertThat(errCaptor.toString()).isNotBlank();
  }

  @Test
  void givenParams_whenSsJwt_printJwt() {
    JwtTokenUtilsConsole.main(Parameters.SSJWT.shortParam, Parameters.SERVICE_ACCOUNT.shortParam,
        TestConstants.SERVICE_ACCOUNT, Parameters.TARGET_SERVICE.shortParam,
        TestConstants.TARGET_SERVICE, Parameters.KEY_FILE.shortParam, TestConstants.KEY_FILE,
        Parameters.TYPE.shortParam, TargetTokenType.ID_TOKEN.val(),
        Parameters.VERBOSE.verboseParam);

    log.info(outCaptor.toString());
    Assertions.assertThat(outCaptor.toString()).isNotBlank().contains(".");
  }

  @Test
  void givenParamsB64_whenSsJwt_printJwt() {
    URL url = this.getClass().getClassLoader().getResource("pk4096.pem");
    String filePath = url.getPath();
    String base64Key =
        assertDoesNotThrow(() -> JwtTokenUtilsInit.builder().build().readPrivateKey(filePath));

    JwtTokenUtilsConsole.main(Parameters.SSJWT.shortParam, Parameters.SERVICE_ACCOUNT.shortParam,
        TestConstants.SERVICE_ACCOUNT, Parameters.TARGET_SERVICE.shortParam,
        TestConstants.TARGET_SERVICE, Parameters.BASE64_KEY.shortParam, base64Key,
        Parameters.TYPE.shortParam, TargetTokenType.ID_TOKEN.val(),
        Parameters.VERBOSE.verboseParam);

    log.info(outCaptor.toString());
    Assertions.assertThat(outCaptor.toString()).isNotBlank().contains(".");
  }

  void givenParams_whenSsJwtVerify_printJwt() {
    JwtTokenUtilsConsole.main(Parameters.SSJWT.shortParam, Parameters.SERVICE_ACCOUNT.shortParam,
        TestConstants.SERVICE_ACCOUNT, Parameters.TARGET_SERVICE.shortParam,
        TestConstants.TARGET_SERVICE, Parameters.KEY_FILE.shortParam, TestConstants.KEY_FILE,
        Parameters.TYPE.shortParam, TargetTokenType.ID_TOKEN.val(),
        Parameters.VERBOSE.verboseParam);

    Assertions.assertThat(outCaptor.toString()).isNotBlank().contains(".");
    String ssJwt = outCaptor.toString();

    JwtTokenUtilsConsole.main(Parameters.SSJWT_VERIFY.shortParam, Parameters.SIGNED_JWT.shortParam,
        ssJwt, Parameters.PUBLIC_KEY.shortParam, TestConstants.PUB_KEY_FILE);
  }

  @Test
  void givenMissParam_whenSsJwt_printError() {
    JwtTokenUtilsConsole.main(Parameters.SSJWT.shortParam, Parameters.SERVICE_ACCOUNT.shortParam,
        TestConstants.SERVICE_ACCOUNT, Parameters.TARGET_SERVICE.shortParam,
        TestConstants.TARGET_SERVICE, Parameters.KEY_FILE.shortParam, TestConstants.KEY_FILE);

    log.info(errCaptor.toString());
    Assertions.assertThat(errCaptor.toString()).isNotBlank();
  }
}


