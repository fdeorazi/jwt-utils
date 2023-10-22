package com.dof.java.jwt;

/**
 *
 *
 * @author fabio.deorazi
 *
 */
public interface JwtTokenUtilsBuilder {
  
  JwtTokenUtilsBuilder setProjectId(String projectId);

  JwtTokenUtilsBuilder setServiceAccount(String serviceAccount);

  JwtTokenUtilsBuilder setBase64PrivateKey(String base64PrivateKey); 

  JwtTokenUtilsBuilder setSharedSecret(String sharedSecret); 

  JwtTokenUtilsBuilder setSignedJwt(String signedJwt); 

  JwtTokenUtilsBuilder setKeyFile(String keyFile); 

  JwtTokenUtilsBuilder setTargetServiceUrl(String targetServiceUrl);

  JwtTokenUtilsBuilder setTargetTokenType(TargetTokenType targetTokenType); 
  
  JwtTokenUtilsBuilder setPublicKeyFile(String publicKeyFile); 
 
  JwtTokenUtilsBuilder setVerbose(boolean verbose); 
  
  JwtTokenUtilsBuilder setScope(String scope);

  JwtTokenUtils build();
  
  
  public String getBase64privateKey();

  public String getProjectId();
    

  public String getServiceAccount();
    

  public String getSharedSecret();
    

  public String getScope();
    

  public String getSignedJwt();
    

  public String getKeyFile();
   
  public String getTargetServiceUrl();
    

  public TargetTokenType getTargetTokenType();
   

  public String getPublicKeyFile();
   

  public boolean isVerbose();
    
  
}
