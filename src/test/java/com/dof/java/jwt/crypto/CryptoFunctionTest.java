package com.dof.java.jwt.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.LogManager;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.JwtTokenUtils;
import com.dof.java.jwt.JwtTokenUtilsDefault;
import com.dof.java.jwt.JwtTokenUtilsInit;
import com.dof.java.jwt.JwtTokenUtilsTest;
import com.dof.java.jwt.TestConstants;

/**
 * 
 *
 * @author fabio.deorazi
 *
 */
class CryptoFunctionTest implements JwtTokenUtilsTest {
  private static final Logger log = LoggerFactory.getLogger(CryptoFunctionTest.class);
  
  @Test
  void givenText_whenSign_thenReturnVerified()
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
    String textToCrypt = "text to crypt";
    
    JwtTokenUtils jwtUtils = JwtTokenUtilsInit.builder().build();

    PrivateKey privateKey = jwtUtils.readPrivateKey(TestConstants.KEY_FILE, "RSA");

    byte[] signedContent = CryptoFunctions.signRsa256(textToCrypt, privateKey);

    assertThat(signedContent).isNotNull();

    PublicKey publicKey = jwtUtils.readPublicKey(TestConstants.PUB_KEY_FILE, "RSA");

    assertTrue(CryptoFunctions.verifySignature(textToCrypt, signedContent, publicKey));
  }

}
