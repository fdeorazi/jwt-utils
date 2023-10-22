package com.dof.java.jwt;

import java.util.Iterator;

/**
 * Utility assertions class.
 *
 * @author fabio.deorazi
 *
 */
public class Assert {

  private Assert() {}

  /**
   * Check only for null object.
   *
   * @param obj Object to check.
   * @param failMessage Message to put in exception.
   * @throws IllegalArgumentException if check is true
   */
  public static void notNull(Object obj, String failMessage) {
    if (obj == null) {
      throw new IllegalArgumentException(failMessage);
    }
  }

  /**
   * Check if a string is not null, empty and black.
   *
   * @param input the string to check
   * @param failMessage the message to put in the exception
   * @throws IllegalArgumentException if check is true
   */
  public static void present(String input, String failMessage) {
    if (input == null || input.matches("\\s*")) {
      throw new IllegalArgumentException(failMessage);
    }
  }

  /**
   * Check if an iterator has a next element.
   *
   * @param iterator the iterator to check if has another element
   * @throws IllegalArgumentException if check is true
   */
  public static void hasNext(Iterator<String> iterator) {
    if (!iterator.hasNext()) {
      throw new IllegalArgumentException("Missed parameter value.");
    }
  }

  /**
   * Checks the length of String.
   *
   * @param input the string to check
   * @param length the minimum length
   */
  public static void atLeast(String input, int length) {
    if (input.length() < 32) {
      throw new IllegalArgumentException(
          "Undersized input. Must be length at least " + (length * 8) + " bits");
    }
  }
}
