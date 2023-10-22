package com.dof.java.jwt.exception;

/**
 * Exception throws when token provider return an error code.
 *
 * @author fabio.deorazi
 * 
 */
public class RequestTokenHttpException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  
  public RequestTokenHttpException(String message) {
    super(message);
  }
}
