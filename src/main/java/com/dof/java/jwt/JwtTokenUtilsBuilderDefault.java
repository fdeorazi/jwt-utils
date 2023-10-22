package com.dof.java.jwt;

import lombok.Getter;
import lombok.Setter;

/**
 * Builder class for JwtTokenUtils.
 * 
 *
 * @author fabio.deorazi
 *
 */
@Getter
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

//  private JwtTokenUtilsContract jwtTokenUtilsContract;
//  private boolean injected;
//
//  public void setJwtTokenUtils(JwtTokenUtilsContract inject) {
//    this.jwtTokenUtilsContract = inject;
//  }

  public JwtTokenUtils build() {
//    if (this.jwtTokenUtilsContract == null || !injected) {
//      this.jwtTokenUtilsContract = new JwtTokenUtilsDefault(this);
//    }
    return new JwtTokenUtilsDefault(this);
  }


}
