package com.dof.java.jwt;

/**
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
  String keyFile;
  String targetServiceUrl;
  TargetTokenType targetTokenType;
  String publicKeyFile;
  boolean verbose;
  

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

  public JwtTokenUtilsBuilder setKeyFile(String keyFile) {
    this.keyFile = keyFile;
    return this;
  }


  public JwtTokenUtilsBuilder setTargetServiceUrl(String targetServiceUrl) {
    this.targetServiceUrl = targetServiceUrl;
    return this;
  }


  public JwtTokenUtilsBuilder setTargetTokenType(TargetTokenType targetTokenType) {
    this.targetTokenType = targetTokenType;
    return this;
  }
  
  
  public JwtTokenUtilsBuilder setPublicKeyFile(String publicKeyFile) {
    this.publicKeyFile = publicKeyFile;
    return this;
  }

  public JwtTokenUtilsBuilder setVerbose(boolean verbose) {
    this.verbose = verbose;
    return this;
  }
  
  public JwtTokenUtilsBuilder setScope(String scope) {
    this.scope = scope;
    return this;
  }

  //@Injected("jwtTokenUtilsImpl")
  //JwtTokenUtils jwtTokenUtils;
  
  public JwtTokenUtils build() {
    return new JwtTokenUtils(this);
  }

}
