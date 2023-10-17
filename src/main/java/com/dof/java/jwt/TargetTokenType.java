package com.dof.java.jwt;

import java.util.Arrays;
import java.util.Optional;

/**
 * Target token type.
 *
 * @author fabio.deorazi
 *
 */
public enum TargetTokenType {
  ID_TOKEN("idtoken"),
  ACCESS_TOKEN("access-token");
  
  String val;
  
  TargetTokenType(String val) {
    this.val = val;
  }
  
  public static TargetTokenType get(String value) {
    Optional<TargetTokenType> result = Arrays.stream(TargetTokenType.values()).filter(item -> value.equals(item.val)).findAny();
    if(result.isEmpty()) {
      throw new IllegalArgumentException("Passed wrong Target Jwt Token type.");
    } else {
      return result.get();
    }  
  }
}
