package com.dof.java.jwt;

import com.dof.java.jwt.enums.TargetTokenType;

/**
 * Default implementation of {@link JwtTokenUtilsBuilder}.
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsBuilderDefault implements JwtTokenUtilsBuilder {


  String base64privateKey;
  String sharedSecret;
  String signedJwt;
  String keyFile;
  TargetTokenType targetTokenType;
  String publicKeyFile;
  boolean verbose;

  String issuer;
  String subject;
  String audience;
  String targetAdience;
  String scope;
  Integer expireIn;

  String targetServiceUrl;
  String serviceAccount;
  String projectId;


  public JwtTokenUtilsBuilderDefault setProjectId(String projectId) {
    this.projectId = projectId;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setServiceAccount(String serviceAccount) {
    this.serviceAccount = serviceAccount;
    return this;
  }

  public JwtTokenUtilsBuilderDefault setBase64privateKey(String base64PrivateKey) {
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

  @Override
  public JwtTokenUtilsBuilder setIssuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  @Override
  public JwtTokenUtilsBuilder setSubject(String subject) {
    this.subject = subject;
    return this;
  }

  @Override
  public JwtTokenUtilsBuilder setAudience(String audience) {
    this.audience = audience;
    return this;
  }

  @Override
  public JwtTokenUtilsBuilder setTargetAudience(String targetAudience) {
    this.targetAdience = targetAudience;
    return this;
  }

  @Override
  public JwtTokenUtilsBuilder setExpireIn(Integer seconds) {
    this.expireIn = seconds;
    return this;
  }

  public String getBase64privateKey() {
    return base64privateKey;
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

  public String getIssuer() {
    return issuer;
  }

  public String getSubject() {
    return subject;
  }

  public String getAudience() {
    return audience;
  }

  public String getScope() {
    return scope;
  }

  public String getTargetAdience() {
    return targetAdience;
  }

  public Integer getExpireIn() {
    return expireIn;
  }

  @Override
  public JwtTokenUtils build() {
    return new JwtTokenUtilsDefault(this);
  }

}
