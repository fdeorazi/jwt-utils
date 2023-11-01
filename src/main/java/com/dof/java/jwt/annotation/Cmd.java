package com.dof.java.jwt.annotation;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import com.dof.java.jwt.JwtTokenUtils;
import com.dof.java.jwt.JwtTokenUtilsConsole;

/**
 * Annotation used in {@link JwtTokenUtilsConsole} to map command line
 * argument to methods in {@link JwtTokenUtils}.
 *
 * @author fabio.deorazi
 *
 */
@Retention(RUNTIME)
@Target(METHOD)
public @interface Cmd {

  /**
   * Return the command names binded to annotated method.
   *
   * @return array of command name.
   */
  String[] param() default {};
}
