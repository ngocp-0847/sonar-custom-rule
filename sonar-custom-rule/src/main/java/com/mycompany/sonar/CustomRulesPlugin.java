package com.mycompany.sonar;

import org.sonar.api.Plugin;
import com.mycompany.sonar.rules.CustomPhpRuleRepository;
import com.mycompany.sonar.rules.LaravelCustomRulesDefinition;
import com.mycompany.sonar.rules.JavaCustomRuleRepository;
import com.mycompany.sonar.rules.SpringBootCustomRulesDefinition;

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
