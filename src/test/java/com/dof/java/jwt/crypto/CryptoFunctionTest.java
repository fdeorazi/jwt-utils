package com.dof.java.jwt.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.LogManager;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.JwtTokenUtils;
import com.dof.java.jwt.JwtTokenUtilsDefault;
import com.dof.java.jwt.JwtTokenUtilsInit;
import com.dof.java.jwt.TestConstants;

/**
 * 
 *
 * @author fabio.deorazi
 *
 */
class CryptoFunctionTest {
  private static final Logger log = LoggerFactory.getLogger(CryptoFunctionTest.class);
  
  @Test
  void givenText_whenSign_thenReturnVerified()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    loggingConf();
    
    JwtTokenUtils jwtUtils = JwtTokenUtilsInit.builder().build();

    PrivateKey privateKey = jwtUtils.readPrivateKey(TestConstants.KEY_FILE_2048, "RSA");
    
    String signedContent = CryptoFunctions.rsa256Signature("text to crypt", privateKey);
    
    log.info(signedContent);
    
    assertThat(signedContent).isNotBlank();
    
    PublicKey publicKey = jwtUtils.readPublicKey(TestConstants.PUB_KEY_FILE_2048, "RSA");
    
    log.info("Signed content: {}", signedContent);
    
    assertTrue(CryptoFunctions.verifySignature("text to crypt", signedContent, publicKey));
  }
  
  private static void loggingConf() {
    try (InputStream in =
        JwtTokenUtilsDefault.class.getClassLoader().getResourceAsStream("logging.properties")) {
      LogManager.getLogManager().readConfiguration(in);
    } catch (IOException e) {
      System.err.printf(e.getMessage());
      System.exit(1);
    }
  }
}
