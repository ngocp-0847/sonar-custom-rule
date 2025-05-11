package com.sunasterisk.sonar.rules;

import org.sonar.api.ExtensionPoint;
import org.sonar.api.batch.ScannerSide;
import org.sonar.plugins.java.api.CheckRegistrar;
import org.sonar.plugins.java.api.JavaCheck;

import java.util.Arrays;
import java.util.List;

/**
 * Provides the list of custom Java checks for Spring Boot
 */
@ExtensionPoint
public class JavaCustomRuleRepository implements CheckRegistrar {
  
  public static final String REPOSITORY_KEY = "custom-spring-boot-java";
  
  @Override
  public void register(RegistrarContext registrarContext) {
    registrarContext.registerClassesForRepository(
      REPOSITORY_KEY,
      Arrays.asList(checkClasses()),
      Arrays.asList(testCheckClasses()));
  }
  
  public static Class<? extends JavaCheck>[] checkClasses() {
    return new Class[] {
      SpringBootSecureCredentialRecoveryCheck.class
    };
  }
  
  public static Class<? extends JavaCheck>[] testCheckClasses() {
    return new Class[] {};
  }
}