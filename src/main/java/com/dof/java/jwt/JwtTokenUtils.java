package com.dof.java.jwt;

import java.io.IOException;

/**
 *
 * @author fabio.deorazi
 *
 */
public interface JwtTokenUtils {
  
  @Cmd(param = "ssjwt")
  String generateSelfSignedJwt();

  String gcpToken(String signedJwt);

  @Cmd(param = "hs256-verify")
  boolean verifyHs256Jwt();

  @Cmd(param = "ssjwt-verify")
  boolean verifyRs256Jwt();
  
  @Cmd(param = "hs256")
  String generateHs256Jwt();
  
  @Cmd(param = {"idtoken", "access-token"})
  String generateToken();
  
  String readPrivateKey(String filePath) throws IOException;
}
