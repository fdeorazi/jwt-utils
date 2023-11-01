package com.dof.java.jwt;

/**
 * Shared constant between tests.
 *
 * @author fabio.deorazi
 *
 */
public class TestConstants {
  private TestConstants() {}

  public static final String SECRET_256_BIT = "tttttttteeeeeeeesssssssstttttttt";

  public static final String SERVICE_ACCOUNT = "service-account-test@test.com";
  public static final String TARGET_SERVICE = "http://cloud.service.com/service";

  public static final String KEY_FILE = "pk4096.pem";
  public static final String PUB_KEY_FILE = "pk4096.pub";
  
  public static final String KEY_FILE_2048 = "pk2048.pem";
  public static final String PUB_KEY_FILE_2048 = "pk2048.pub";
  
  public static final String GCP_SCOPE = "https://www.googleapis.com/auth/compute";

}
