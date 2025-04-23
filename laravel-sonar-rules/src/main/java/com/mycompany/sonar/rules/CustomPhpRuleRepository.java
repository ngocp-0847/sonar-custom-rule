package com.mycompany.sonar.rules;

import org.sonar.api.ExtensionPoint;
import org.sonar.api.batch.ScannerSide;
import org.sonar.plugins.php.api.visitors.PHPCustomRuleRepository;

import java.util.Arrays;
import java.util.List;

@ScannerSide
@ExtensionPoint
public class CustomPhpRuleRepository implements PHPCustomRuleRepository {

  @Override
  public String repositoryKey() {
    return "custom-laravel-php";
  }

  @Override
  public List<Class<?>> checkClasses() {
    return Arrays.asList(
      LaravelMassAssignmentCheck.class,
      LaravelPlaintextOTPCheck.class
    );
  }
}
