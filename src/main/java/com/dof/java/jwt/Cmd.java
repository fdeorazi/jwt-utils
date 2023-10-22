package com.dof.java.jwt;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 *
 * @author fabio.deorazi
 *
 */
@Retention(RUNTIME)
@Target(METHOD)
public @interface Cmd {

  /**
   *
   * @return
   */
  String[] param() default {};
}
