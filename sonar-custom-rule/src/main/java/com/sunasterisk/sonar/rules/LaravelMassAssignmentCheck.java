package com.sunasterisk.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.check.Priority;
import org.sonar.plugins.php.api.visitors.PHPVisitorCheck;
import org.sonar.plugins.php.api.tree.Tree;
import org.sonar.plugins.php.api.tree.Tree.Kind;
import org.sonar.plugins.php.api.tree.expression.FunctionCallTree;
import org.sonar.plugins.php.api.tree.expression.MemberAccessTree;
import org.sonar.plugins.php.api.tree.expression.ExpressionTree;
import org.sonar.plugins.php.api.tree.expression.LiteralTree;
import org.sonar.plugins.php.api.tree.declaration.ClassDeclarationTree;
import org.sonar.plugins.php.api.tree.declaration.ClassPropertyDeclarationTree;
import org.sonar.plugins.php.api.tree.expression.IdentifierTree;
import org.sonar.plugins.php.api.symbols.Symbol;
import org.sonar.plugins.php.api.visitors.PHPSubscriptionCheck;
import org.sonar.plugins.php.api.visitors.CheckContext;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
// Add SLF4J imports
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Rule(
  key = "LaravelMassAssignmentForCS1.1.1",
  name = "Detect unsafe mass assignment in Laravel",
  priority = Priority.CRITICAL,
  tags = {"security", "laravel", "mass-assignment"}
)
public class LaravelMassAssignmentCheck extends PHPSubscriptionCheck {

  private static final List<String> UNSAFE_METHODS = Arrays.asList("create", "fill", "update");
  private static final List<String> UNSAFE_REQUEST_METHODS = Arrays.asList("all", "input");

  // Add logger initialization
  private static final Logger LOGGER = LoggerFactory.getLogger(LaravelMassAssignmentCheck.class);

  @Override
  public List<Kind> nodesToVisit() {
    return Collections.singletonList(Kind.FUNCTION_CALL);
  }

  @Override
  public void visitNode(Tree tree) {
    FunctionCallTree functionCall = (FunctionCallTree) tree;
    // Check if it's a function call
    if (!functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) &&
        !functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      return;
    }

    // Add log to check tree type
    LOGGER.info("Function call detected: {}", functionCall);

    // Check if this is a Model::create(), $model->fill() or $model->update() call
    if (functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) || 
        functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      
      MemberAccessTree memberAccess = (MemberAccessTree) functionCall.callee();
      // Fix: Get method name from member access
      String methodName = ((IdentifierTree)memberAccess.member()).text();
      LOGGER.info("Method name: {}", methodName);
      
      // Check if the method is in the list of unsafe methods
      if (UNSAFE_METHODS.contains(methodName)) {
        LOGGER.info("Found unsafe method: {}", methodName);
        
        // Check what the first parameter of the method is
        if (!functionCall.arguments().isEmpty()) {
          ExpressionTree firstArgument = functionCall.arguments().get(0);
          LOGGER.info("First argument type: {}", firstArgument.getClass().getSimpleName());
          
          // Check if the first parameter is $request->all() or $request->input()
          if (firstArgument.is(Kind.FUNCTION_CALL)) {
            FunctionCallTree argFunctionCall = (FunctionCallTree) firstArgument;
            LOGGER.info("First argument is a function call: {}", argFunctionCall.toString().replaceAll("\\s+", " ").trim());
            
            if (argFunctionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS)) {
              MemberAccessTree argMemberAccess = (MemberAccessTree) argFunctionCall.callee();
              // Fix: Get method name from member access
              String argMethodName = ((IdentifierTree)argMemberAccess.member()).text();
              LOGGER.info("Argument method name: {}", argMethodName);
              
              if (UNSAFE_REQUEST_METHODS.contains(argMethodName)) {
                // This is a mass assignment vulnerability
                context().newIssue(this, tree, 
                  "Unsafe mass assignment detected: Using " + methodName + "() with " + 
                  argMethodName + "() can lead to mass assignment vulnerabilities. " + 
                  "Make sure $fillable or $guarded is properly set in the model.");
              }
            }
          }
          
          // Check for $request->all() case
          if (firstArgument.is(Kind.VARIABLE_IDENTIFIER)) {
            // Detect direct variables like $request or $input
            String varName = firstArgument.toString();
            LOGGER.info("First argument is a variable: {}", varName);
            
            if (varName.contains("request") || varName.contains("input")) {
              context().newIssue(this, tree,
                "Potential unsafe mass assignment detected: Using " + methodName + "() with " + 
                varName + " can lead to mass assignment vulnerabilities. " +
                "Make sure $fillable or $guarded is properly set in the model.");
            }
          }
        } else {
          LOGGER.info("No arguments found for unsafe method call");
        }
      }
    }
  }
}
