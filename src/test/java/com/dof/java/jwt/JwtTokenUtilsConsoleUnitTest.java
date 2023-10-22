package com.dof.java.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.dof.java.jwt.JwtTokenUtilsConsole.Parameters;

@ExtendWith(MockitoExtension.class)
class JwtTokenUtilsConsoleUnitTest {
  Logger log = LoggerFactory.getLogger(JwtTokenUtilsConsoleUnitTest.class);

  @Mock
  JwtTokenUtilsBuilder builder;

  @Mock
  JwtTokenUtils jwtTokenUtils;


  @Test
  void givenParams_whenHs256_printJwt() throws Exception {
    when(builder.build()).thenReturn(jwtTokenUtils);
    when(jwtTokenUtils.generateHs256Jwt()).thenReturn("testMock");
    
    JwtTokenUtilsConsole jwtConsole = new JwtTokenUtilsConsole(builder);
    
    assertDoesNotThrow(() -> jwtConsole.evalMethod(Parameters.HS256.shortParam, 
        Parameters.SECRET.shortParam, TestConstants.SECRET_256_BIT));
    
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    
    verify(builder, times(1)).setSharedSecret(captor.capture());
    verify(jwtTokenUtils, times(1)).generateHs256Jwt();
    assertThat(captor.getValue()).isEqualTo((TestConstants.SECRET_256_BIT));
  }
}
