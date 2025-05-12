package com.sunasterisk.sonar;

import org.sonar.api.Plugin;

import com.sunasterisk.sonar.rules.CustomPhpRuleRepository;
import com.sunasterisk.sonar.rules.JavaCustomRuleRepository;
import com.sunasterisk.sonar.rules.LaravelCustomRulesDefinition;
import com.sunasterisk.sonar.rules.SpringBootCustomRulesDefinition;

/**
 * Entry point of plugin
 */
public class CustomRulesPlugin implements Plugin {

  @Override
  public void define(Context context) {
    // Register the PHP custom rules repository
    context.addExtension(CustomPhpRuleRepository.class);
    
    // Register the PHP rules definition
    context.addExtension(LaravelCustomRulesDefinition.class);
    
    // Register the Java custom rules repository
    context.addExtension(JavaCustomRuleRepository.class);
    
    // Register the Java rules definition
    context.addExtension(SpringBootCustomRulesDefinition.class);
  }
}
