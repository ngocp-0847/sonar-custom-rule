package com.mycompany.sonar;

import org.sonar.api.Plugin;
import com.mycompany.sonar.rules.CustomPhpRuleRepository;
import com.mycompany.sonar.rules.LaravelCustomRulesDefinition;

/**
 * Entry point of plugin
 */
public class LaravelCustomRulesPlugin implements Plugin {

  @Override
  public void define(Context context) {
    // Register the custom rules repository
    context.addExtension(CustomPhpRuleRepository.class);
    
    // Register the rules definition
    context.addExtension(LaravelCustomRulesDefinition.class);
  }
}
