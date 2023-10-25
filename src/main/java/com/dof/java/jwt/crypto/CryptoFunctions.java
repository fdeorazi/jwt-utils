/*
 * Copyright 2023 Fabio De Orazi
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.dof.java.jwt.crypto;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.IntStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.exception.JwtTokenUtilsException;

/**
 * Utility class with sign and sign verification methods.
 *
 * @author fabio.deorazi
 */
public class CryptoFunctions {
  private static final Logger log = LoggerFactory.getLogger(CryptoFunctions.class);

  private CryptoFunctions() {}

  /**
   * Split JWT and pass to {@link #verifySignature(String, String, PublicKey)}
   * for signature verification.
   * 
   * @param signedJwt
   * @param publicKey
   * @return
   * @throws IOException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws InvalidKeyException
   */
  public static boolean verifyJwtSignature(String signedJwt, PublicKey publicKey)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
      NoSuchAlgorithmException, NoSuchPaddingException, IOException {
    String[] jwtSplit = signedJwt.split("\\.");
    byte[] signatureBase64 = jwtSplit[2].getBytes();
    byte[] signature = Base64.getDecoder().decode(signatureBase64);
    log.debug("Verifying signature ({} bytes):\nBase64:\n'{}'", signature.length,
        new String(signatureBase64));

    return verifySignature(String.format("%s.%s", jwtSplit[0], jwtSplit[1]), signature, publicKey);
  }

  /**
   * Verify JWT signature for HS256 signed JWT.
   * 
   * @param signedJwt
   *        JWT to verify
   * @param key
   *        The secret used in HMAC digital signature
   * @return if the signature is verified
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   */
  public static boolean verifyJwtSignature(String signedJwt, String key)
      throws InvalidKeyException, NoSuchAlgorithmException {
    String[] jwtSplit = signedJwt.split("\\.");
    byte[] signatureBase64 = jwtSplit[2].getBytes();
    byte[] signature = Base64.getDecoder().decode(signatureBase64);

    byte[] computedHmac = signHs256(String.format("%s.%s", jwtSplit[0], jwtSplit[1]), key);

    log.debug("HMAC Signature:\n{}\n", new String(signature));
    log.debug("Computed HMAC:\n{}", new String(computedHmac));
    
    return Arrays.equals(signature, computedHmac);
  }

  /**
   * Sign data with RS256 algorithm.
   * 
   * @param data
   *        data to sign 
   * @param privateKey
   *        to use in signature
   * @return
   * @throws IOException
   */
  public static byte[] signRsa256(String data, PrivateKey privateKey) throws IOException {
    try {
      byte[] hashMessage = messageDigest(data);
      log.debug("Message digest (SHA-256)({}):\n{}\n", hashMessage.length, toHex(hashMessage));

      // encode hash message
      byte[] encodedHashMessage = digestInfoEncoded(hashMessage);
      log.debug("Encoded message digest: \n{}\n", toHex(encodedHashMessage));

      Cipher chiper = Cipher.getInstance("RSA");
      chiper.init(Cipher.ENCRYPT_MODE, privateKey);
      byte[] encryptEncodMessageHash = chiper.doFinal(encodedHashMessage);

      log.debug("Encrypted encoded message digest:\n{}\n", toHex(encryptEncodMessageHash));

      return encryptEncodMessageHash;

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | IllegalBlockSizeException | BadPaddingException e) {
      throw new JwtTokenUtilsException(e.getMessage());
    }
  }
  
  /**
   * Sign a JWT with HMAC SAH-256 signature.
   * 
   * @param data
   * @param key
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  public static byte[] signHs256(String data, String key)
      throws NoSuchAlgorithmException, InvalidKeyException {
    String algorithm = "HmacSHA256";
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
    Mac mac = Mac.getInstance(algorithm);
    mac.init(secretKeySpec);
    return mac.doFinal(data.getBytes());
  }

  /**
   * Verify validity of an asymmetric signature of RS256 type.
   *
   * @param content
   *        Clear data
   * @param encryptedContentHash
   *        Encrypted and signed hash message
   * @param publicKey
   *        The public key used in asymmetric signature verification
   * @return
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws IOException
   */
  public static boolean verifySignature(String content, byte[] encryptedContentHash,
      PublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException,
      InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {

    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, publicKey);
    byte[] decryptedMessageHash = cipher.doFinal(encryptedContentHash);

    log.debug("Decrypted Encoded Message Hash:\n{}", toHex(decryptedMessageHash));

    // compute hash message
    byte[] hashMessage = messageDigest(content);
    byte[] encodedHashMessage = digestInfoEncoded(hashMessage);

    log.debug("Computed Encoded Message Hash:\n{}", toHex(decryptedMessageHash));

    return Arrays.equals(decryptedMessageHash, encodedHashMessage);
  }

  private static String toHex(byte[] content) {
    StringBuffer hexString = new StringBuffer();
    IntStream.range(0, content.length)
        .forEach(i -> hexString.append(Integer.toHexString(0xFF & content[i])));
    return hexString.toString();
  }

  private static byte[] messageDigest(String content) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(content.getBytes());
    return messageDigest.digest();
  }

  private static byte[] digestInfoEncoded(byte[] hashMessage) throws IOException {
    DigestAlgorithmIdentifierFinder hashAlgorithmFinder =
        new DefaultDigestAlgorithmIdentifierFinder();
    AlgorithmIdentifier hashingAlgorithmIdentifier = hashAlgorithmFinder.find("SHA-256");
    DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashMessage);
    return digestInfo.getEncoded();
  }
}
