package com.dof.java.jwt.enums;

import java.util.Arrays;
import java.util.Optional;

/**
 * Target token type.
 *
 * @author fabio.deorazi
 *
 */
public enum TargetTokenType {
  ID_TOKEN("idtoken"), ACCESS_TOKEN("access-token"), SIGN_ONLY("sign-only");

  String val;

  public String val() {
    return this.val;
  }
  
  TargetTokenType(String val) {
    this.val = val;
  }
  
  /**
   * Iterate enumeration to matching an element based on given value.
   *
   * @param value The value of enumeration element to lookup.
   * @return the matching enumeration element.
   */
  public static TargetTokenType get(String value) {
    Optional<TargetTokenType> result =
        Arrays.stream(TargetTokenType.values()).filter(item -> value.equals(item.val)).findAny();
    if (result.isEmpty()) {
      throw new IllegalArgumentException("Passed wrong Target Jwt Token type.");
    } else {
      return result.get();
    }
  }
}
