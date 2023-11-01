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

  private static final String RSA = "RSA";

  private CryptoFunctions() {}

  /**
   * Split JWT and pass to {@link #verifySignature(String, String, PublicKey)} for signature
   * verification.
   *
   * @param signedJwt The signed Jwt to verify.
   * @param publicKey The respective public key for signature verification.
   * @return if verified
   */
  public static boolean verifyJwtSignature(String signedJwt, PublicKey publicKey) {
    String[] jwtSplit = signedJwt.split("\\.");
    byte[] signatureBase64 = jwtSplit[2].getBytes();
    byte[] signature = Base64.getDecoder().decode(signatureBase64);

    if (log.isDebugEnabled()) {
      log.debug("Verifying signature ({} bytes):\nBase64:\n'{}'", signature.length,
          new String(signatureBase64));
    }

    return verifySignature(String.format("%s.%s", jwtSplit[0], jwtSplit[1]), signature, publicKey);
  }

  /**
   * Verify JWT signature for HS256 signed JWT.
   *
   * @param signedJwt JWT to verify
   * @param key The secret used in HMAC digital signature
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

    if (log.isTraceEnabled()) {
      log.trace("HMAC Signature:\n{}\n", new String(signature));
      log.trace("Computed HMAC:\n{}", new String(computedHmac));
    }
    return Arrays.equals(signature, computedHmac);
  }

  /**
   * Sign data with RS256 algorithm.
   * 
   * @param data data to sign
   * @param privateKey to use in signature
   * @return
   * @throws IOException
   */
  public static byte[] signRsa256(String data, PrivateKey privateKey) throws IOException {
    try {
      byte[] hashMessage = messageDigest(data);

      byte[] encodedHashMessage = digestInfoEncoded(hashMessage);

      Cipher chiper = Cipher.getInstance(RSA);
      chiper.init(Cipher.ENCRYPT_MODE, privateKey);
      byte[] encryptEncodMessageHash = chiper.doFinal(encodedHashMessage);

      if (log.isTraceEnabled()) {
        log.trace("Message digest (SHA-256)({}):\n{}\n", hashMessage.length, toHex(hashMessage));
        log.trace("Encoded message digest: \n{}\n", toHex(encodedHashMessage));
        log.trace("Encrypted encoded message digest:\n{}\n", toHex(encryptEncodMessageHash));
      }

      return encryptEncodMessageHash;

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | IllegalBlockSizeException | BadPaddingException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
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
   * Verify validity of an asymmetric signature of RS256 type. It takes
   * {@code content} content argument to self generate the digest message to use then in matching
   * with decrypted digest message for key validity evaluation.
   *
   * @param content clear content
   * @param encryptedContentHash Encrypted and signed hash message
   * @param publicKey The public key used in asymmetric signature verification
   * @return if signature is verified
   * @throws JwtTokenUtilsException if an error occurrs during verification.
   */
  public static boolean verifySignature(String content, byte[] encryptedContentHash,
      PublicKey publicKey) {
    try {
      Cipher cipher;

      cipher = Cipher.getInstance(RSA);

      cipher.init(Cipher.DECRYPT_MODE, publicKey);
      byte[] decryptedMessageHash = cipher.doFinal(encryptedContentHash);

      // compute hash message
      byte[] hashMessage = messageDigest(content);
      byte[] encodedHashMessage = digestInfoEncoded(hashMessage);

      if (log.isTraceEnabled()) {
        log.trace("Decrypted Encoded Message Hash:\n{}", toHex(decryptedMessageHash));
        log.trace("Computed Encoded Message Hash:\n{}", toHex(encodedHashMessage));
      }

      return Arrays.equals(decryptedMessageHash, encodedHashMessage);

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException
        | IllegalBlockSizeException | BadPaddingException e) {
      throw new JwtTokenUtilsException(e.getMessage(), e);
    }
  }

  private static String toHex(byte[] content) {
    StringBuilder hexString = new StringBuilder();
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
