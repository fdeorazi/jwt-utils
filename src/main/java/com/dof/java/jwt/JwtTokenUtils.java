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

package com.dof.java.jwt;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import com.dof.java.jwt.annotation.Cmd;
import com.dof.java.jwt.enums.TargetTokenType;


/**
 * Jar utility to generate token Json Web Token through an issuer and a private key.
 *
 * @author fabio.deorazi
 *
 */
public interface JwtTokenUtils {

  /**
   * Generate a self signed JWT to request and Identity Token (OpenID conform) or an Access Token
   * (Oauth2 conform) to GCP end point. Required properties parameter configurable by builder
   * methods are: {@link JwtTokenUtilsBuilder#setTargetTokenType(TargetTokenType)} In case of
   * Identity Token: {@link JwtTokenUtilsBuilder#setTargetServiceUrl(String)}
   *
   * @return the self signed JWT
   */
  @Cmd(param = "ssjwt")
  String generateSelfSignedJwt();

  /**
   * Request a token at GCP token endpoint.
   *
   * @param signedJwt self RS256 signed JWT
   * @return the final gcp access token
   */
  String gcpToken(String signedJwt);

  /**
   * Verify the signature of a given signed HS256 JWT.
   *
   * @return Return the outcome of signature verification.
   */
  @Cmd(param = "hs256-verify")
  boolean verifyHs256Jwt();

  /**
   * Verify the signature of a given signed RS256 JWT.
   *
   * @return Return the outcome of signature verification.
   */
  @Cmd(param = "ssjwt-verify")
  boolean verifyRs256Jwt();

  /**
   * Create a HMAC SHA-256 jwt signed with the given secret.
   *
   * @return the signed JWT.
   */
  @Cmd(param = "hs256")
  String generateHs256Jwt();

  /**
   * Generate and Identity Token or Access Token based on {@link TargetTokenType}.
   *
   * @return The requested token of type Identity Token or Access Token
   */
  @Cmd(param = {"idtoken", "access-token"})
  String generateToken();

  String readPrivateKey(String filePath) throws IOException;


  PrivateKey readPrivateKey(String filePath, String algorithm)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException;
  
  String readPublicKey(String filePath) throws IOException;
  
  PublicKey readPublicKey(String filePath, String algorithm)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException;
}
