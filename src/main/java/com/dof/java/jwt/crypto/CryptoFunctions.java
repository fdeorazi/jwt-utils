package com.dof.java.jwt.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import com.dof.java.jwt.exception.JwtTokenUtilsException;

public class CryptoFunctions {

  
  public static String rsa256Signature(String content, PrivateKey privateKey) {
    
    try {
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initSign(privateKey);
      signature.update(content.getBytes());
      byte[] digitalSignature = signature.sign();
      return new String(Base64.getEncoder().encode(digitalSignature), StandardCharsets.UTF_8);
    } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
      throw new JwtTokenUtilsException(e.getMessage());
    }
    
  }
  
  public static boolean verifySignature(String signedJwt, PublicKey publicKey) {
    try {
      String[] jwtSplit = signedJwt.split("\\.");
      String headerClaims = String.format("%s.%s", jwtSplit[0], jwtSplit[1]);
      
      Signature signature = Signature.getInstance("SHA256withRSA");
      signature.initVerify(publicKey);
      signature.update(headerClaims.getBytes(StandardCharsets.UTF_8));
      return signature.verify(jwtSplit[2].getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new JwtTokenUtilsException(e.getMessage());
    }
  }
  
  
  public static String rsa256Signature2(String content, PrivateKey privateKey) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
      byte[] messageHash = messageDigest.digest(content.getBytes(StandardCharsets.UTF_8));

      Cipher chiper = Cipher.getInstance("RSA");
      chiper.init(Cipher.ENCRYPT_MODE, privateKey);
      byte[] encryptedMessage =  chiper.doFinal(messageHash);
      
      // Charset.forName("US-ASCII");
      return new String(Base64.getEncoder().encode(encryptedMessage), StandardCharsets.UTF_8);
      
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | IllegalBlockSizeException | BadPaddingException e) {
      throw new JwtTokenUtilsException(e.getMessage());
    }
  }
}
