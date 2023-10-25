package com.dof.java.jwt;

import com.dof.java.jwt.enums.TargetTokenType;

/**
 * Builder interface for constructing a parameterized {@link JwtTokenUtils} instance 
 * to create self signed JWT or request OpenID token and Access Token.
 *
 * @author fabio.deorazi
 *
 */
public interface JwtTokenUtilsBuilder {

  /**
   * The id of Google Cloud Project used in {@link TargetTokenType#SIGN_ONLY}.
   *
   * @param projectId Google Cloud Project Id
   * @return the builder for method chaining.
   */
  JwtTokenUtilsBuilder setProjectId(String projectId);

  /**
   * Set the Google Cloud service account used as subject ('sub') claim on a Signed JWT to 
   * request and Identity Token.
   *
   * @param serviceAccount Google Cloud service account
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setServiceAccount(String serviceAccount);

  /**
   * Set the private key content in Base64 format used in JWT signature on 
   * {@link JwtTokenUtils#generateSelfSignedJwt()} method.
   *
   * @param base64PrivateKey 
   *        PEM private key content
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setBase64PrivateKey(String base64PrivateKey);
  
  /**
   * Set the secret used to sign or verify the HS256 JWT Token.
   *
   * @param sharedSecret 256bit ASCII secret.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setSharedSecret(String sharedSecret);
  
  /**
   * Set the Signed JWT used in {@link JwtTokenUtils#verifyHs256Jwt()} and 
   * {@link JwtTokenUtils#verifyRs256Jwt()} methods.
   *
   * @param signedJwt A self signed JWT.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setSignedJwt(String signedJwt);
  
  /**
   * Set private key file path used for self signed JWT signature. It is used 
   * in {@link JwtTokenUtils#generateSelfSignedJwt()} method.
   *
   * @param keyFile 
   *        Private key file path.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setKeyFile(String keyFile);

  /**
   * Set the URL of target service used in 'target_audience' claim in signed JWT to
   * request an Identity Token.
   *
   * @param targetServiceUrl the service endpoint to which to authenticate
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setTargetServiceUrl(String targetServiceUrl);

  /**
   * Set final token type to request on GCP token endpoint. The value is
   * in {@link TargetTokenType} enumeration.
   *
   * @param targetTokenType Token type.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setTargetTokenType(TargetTokenType targetTokenType);
  
  /**
   * Set the path of public key used in JWT RS256 signed. 
   *
   * @param publicKeyFile The path of public key file.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilderDefault setPublicKeyFile(String publicKeyFile);

  /**
   * Set if verbose in standard out.
   * This includes printing of header and claim of self signed JWT and
   * no-opaque identity-token.
   *
   * @param verbose True to print in verbose mode.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setVerbose(boolean verbose);

  /**
   * Set the scope used as 'scope' claim in signed JWT to request an Access Token.
   * If not specified the default is used.
   *
   * @param scope The scope in Access Token.
   * @return the builder for method chaining
   */
  JwtTokenUtilsBuilder setScope(String scope);

  /**
   * Pass setted parameter to a new {@link JwtTokenUtils} on which can be invoked
   * utility JWT and token methods.
   *
   * @return the builder for method chaining
   */
  JwtTokenUtils build();

  /**
   * Get the private key set in builder on {@link #setBase64PrivateKey(String)}. 
   *
   * @return The private Base64 key content.
   */
  String getBase64privateKey();

  /**
   * Get the project id set in builder on {@link #setProjectId(String)}.
   *
   * @return The d of Google Cloud project.
   */
  String getProjectId();

  /**
   * Get the service account set in builder on {@link #setServiceAccount(String)}.
   *
   * @return The service account
   */
  String getServiceAccount();
  
  /**
   * Get the secret set in builder on {@link #setSharedSecret(String)}.
   *
   * @return The secret used in signature.
   */
  String getSharedSecret();
  
  /**
   * Get the scope set in builder on {@link #setScope(String)}.
   *
   * @return The scope
   */
  String getScope();

  /**
   * Get the signed JWT set in builder on {@link #setSignedJwt(String)}.
   *
   * @return Signed JWT
   */
  String getSignedJwt();

  /**
   * Get the private key file path set in builder {@link #setKeyFile(String)}.
   *
   * @return The private key file path.
   */
  String getKeyFile();

  /**
   * Get the target service url set on builder.
   *
   * @return The set target service url.
   */
  String getTargetServiceUrl();
  
  /**
   * The path of public key file set in builder {@link #setPublicKeyFile(String)}.
   *
   * @return The path of public key file.
   */
  String getPublicKeyFile();
  
  /**
   * Get the target token type set in builder on {@link #setTargetTokenType(TargetTokenType)}.
   *
   * @return The target token type.
   */
  TargetTokenType getTargetTokenType();

  /**
   * Get if builder was set as verbose {@link #setVerbose(boolean)}.
   *
   * @return If builder was set as verbose.
   */
  boolean isVerbose();


}
