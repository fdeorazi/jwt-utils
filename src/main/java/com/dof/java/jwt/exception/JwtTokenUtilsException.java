package com.dof.java.jwt.exception;

/**
 * Generic exception to embrace various error messages.
 *
 * @author fabio.deorazi
 *
 */
public class JwtTokenUtilsException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public JwtTokenUtilsException(String message) {
    super(message);
  }
  
  public JwtTokenUtilsException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
