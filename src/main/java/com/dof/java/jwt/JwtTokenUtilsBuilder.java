package com.dof.java.jwt;

/**
 *
 * Builder class for JwtTokenUtils.
 * 
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsBuilder {

  String projectId;
  String serviceAccount;
  String base64privateKey;
  String sharedSecret;
  String scope;
  String signedJwt;


  public JwtTokenUtilsBuilder setProjectId(String projectId) {
    this.projectId = projectId;
    return this;
  }

  public JwtTokenUtilsBuilder setServiceAccount(String serviceAccount) {
    this.serviceAccount = serviceAccount;
    return this;
  }

  public JwtTokenUtilsBuilder setBase64PrivateKey(String base64PrivateKey) {
    this.base64privateKey = base64PrivateKey;
    return this;
  }

  public JwtTokenUtilsBuilder setSharedSecret(String sharedSecret) {
    this.sharedSecret = sharedSecret;
    return this;
  }

  public JwtTokenUtilsBuilder setSignedJwt(String signedJwt) {
    this.signedJwt = signedJwt;
    return this;
  }

  public JwtTokenUtils build() {
    return new JwtTokenUtils(this);
  }

}
