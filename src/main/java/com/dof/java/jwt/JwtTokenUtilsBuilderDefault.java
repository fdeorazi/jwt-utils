package com.dof.java.jwt;

import com.dof.java.jwt.enums.TargetTokenType;

/**
 * Default implementation of {@link JwtTokenUtilsBuilder}.
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsBuilderDefault implements JwtTokenUtilsBuilder {

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


  public JwtTokenUtilsBuilderDefault setProjectId(String projectId) {
    this.projectId = projectId;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setServiceAccount(String serviceAccount) {
    this.serviceAccount = serviceAccount;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setBase64PrivateKey(String base64PrivateKey) {
    this.base64privateKey = base64PrivateKey;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setSharedSecret(String sharedSecret) {
    this.sharedSecret = sharedSecret;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setSignedJwt(String signedJwt) {
    this.signedJwt = signedJwt;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setKeyFile(String keyFile) {
    this.keyFile = keyFile;
    return this;
  }


  public JwtTokenUtilsBuilderDefault setTargetServiceUrl(String targetServiceUrl) {
    this.targetServiceUrl = targetServiceUrl;
    return this;
  }


  public JwtTokenUtilsBuilderDefault setTargetTokenType(TargetTokenType targetTokenType) {
    this.targetTokenType = targetTokenType;
    return this;
  }


  public JwtTokenUtilsBuilderDefault setPublicKeyFile(String publicKeyFile) {
    this.publicKeyFile = publicKeyFile;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setVerbose(boolean verbose) {
    this.verbose = verbose;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setScope(String scope) {
    this.scope = scope;
    return this;
  }

  public String getBase64privateKey() {
    return base64privateKey;
  }

  public void setBase64privateKey(String base64privateKey) {
    this.base64privateKey = base64privateKey;
  }

  public String getProjectId() {
    return projectId;
  }

  public String getServiceAccount() {
    return serviceAccount;
  }

  public String getSharedSecret() {
    return sharedSecret;
  }

  public String getScope() {
    return scope;
  }

  public String getSignedJwt() {
    return signedJwt;
  }

  public String getKeyFile() {
    return keyFile;
  }

  public String getTargetServiceUrl() {
    return targetServiceUrl;
  }

  public TargetTokenType getTargetTokenType() {
    return targetTokenType;
  }

  public String getPublicKeyFile() {
    return publicKeyFile;
  }

  public boolean isVerbose() {
    return verbose;
  }

  @Override
  public JwtTokenUtils build() {
    return new JwtTokenUtilsDefault(this);
  }


}
