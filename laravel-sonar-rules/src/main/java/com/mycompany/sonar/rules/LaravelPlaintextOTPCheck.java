package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.check.Priority;
import org.sonar.plugins.php.api.tree.Tree;
import org.sonar.plugins.php.api.tree.Tree.Kind;
import org.sonar.plugins.php.api.tree.expression.FunctionCallTree;
import org.sonar.plugins.php.api.tree.expression.MemberAccessTree;
import org.sonar.plugins.php.api.tree.expression.VariableIdentifierTree;
import org.sonar.plugins.php.api.tree.expression.ExpressionTree;
import org.sonar.plugins.php.api.tree.expression.LiteralTree;
import org.sonar.plugins.php.api.tree.expression.ArrayInitializerTree;
import org.sonar.plugins.php.api.tree.expression.ArrayPairTree;
import org.sonar.plugins.php.api.tree.declaration.ClassDeclarationTree;
import org.sonar.plugins.php.api.tree.declaration.ClassPropertyDeclarationTree;
import org.sonar.plugins.php.api.tree.expression.IdentifierTree;
import org.sonar.plugins.php.api.tree.expression.AssignmentExpressionTree;
import org.sonar.plugins.php.api.tree.statement.ExpressionStatementTree;
import org.sonar.plugins.php.api.visitors.PHPSubscriptionCheck;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Pattern;

@Rule(
  key = "LaravelPlaintextOTP",
  name = "OTP values should never be stored in plaintext",
  priority = Priority.CRITICAL,
  tags = {"security", "laravel", "otp", "plaintext"}
)
public class LaravelPlaintextOTPCheck extends PHPSubscriptionCheck {

  private static final Logger LOGGER = LoggerFactory.getLogger(LaravelPlaintextOTPCheck.class);
  
  // Define patterns for OTP variable names
  private static final Pattern OTP_VAR_PATTERN = Pattern.compile("(?i)\\botp\\b|one.?time.?password|verification.?code|auth.?code");
  
  // List of methods that should not receive plaintext OTP
  private static final List<String> UNSAFE_DB_METHODS = Arrays.asList(
      "create", "insert", "save", "update", "execute"
  );
  
  // List of Laravel storage mechanisms that should not store OTP
  private static final List<String> UNSAFE_STORAGE_METHODS = Arrays.asList(
      "put", "set", "add", "remember", "forever", "store"
  );
  
  // List of classes/contexts where OTP should not be stored in plaintext
  private static final List<String> SENSITIVE_STORAGE_CLASSES = Arrays.asList(
      "db", "database", "session", "cache", "redis", "cookie", "storage", "log"
  );

  @Override
  public List<Kind> nodesToVisit() {
    return Arrays.asList(
        Kind.FUNCTION_CALL,            // For DB operations and logging functions
        Kind.ASSIGNMENT,               // For session storage like $_SESSION['otp'] = $otp
        Kind.ARRAY_INITIALIZER_FUNCTION // For array initializers in create() methods
    );
  }

  @Override
  public void visitNode(Tree tree) {
    switch (tree.getKind()) {
      case FUNCTION_CALL:
        checkFunctionCall((FunctionCallTree) tree);
        break;
      case ASSIGNMENT:
        checkAssignment((AssignmentExpressionTree) tree);
        break;
      case ARRAY_INITIALIZER_FUNCTION:
        checkArrayInitializer((ArrayInitializerTree) tree);
        break;
      default:
        // Not interested in other tree types
    }
  }

  private void checkFunctionCall(FunctionCallTree functionCall) {
    // Case 1: Check for ORM operations with plaintext OTP - Model::create(['otp' => $otp])
    if (functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) || 
        functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      
      MemberAccessTree memberAccess = (MemberAccessTree) functionCall.callee();
      String methodName = ((IdentifierTree) memberAccess.member()).text();

      if (UNSAFE_DB_METHODS.contains(methodName.toLowerCase())) {
        // Check if the arguments contain plaintext OTP
        checkArgumentsForPlaintextOTP(functionCall, methodName);
      }
      
      // Case 2: Check logging functions containing OTP values
      if (methodName.equalsIgnoreCase("log") || 
          methodName.equalsIgnoreCase("info") ||
          methodName.equalsIgnoreCase("error") ||
          methodName.equalsIgnoreCase("debug") ||
          methodName.equalsIgnoreCase("warning")) {
        
        checkLogStatementsForOTP(functionCall);
      }
      
      // Case 3: Check cache/session storage with plaintext OTP
      if (UNSAFE_STORAGE_METHODS.contains(methodName.toLowerCase())) {
        ExpressionTree object = memberAccess.object();
        if (object.is(Kind.VARIABLE_IDENTIFIER) || object.is(Kind.NAMESPACE_NAME)) {
          String objectName = object.toString().toLowerCase();
          for (String sensitiveClass : SENSITIVE_STORAGE_CLASSES) {
            if (objectName.contains(sensitiveClass)) {
              checkArgumentsForPlaintextOTP(functionCall, methodName);
              break;
            }
          }
        }
      }
    }
    
    // Case 4: Check direct SQL queries with OTP
    String functionName = functionCall.callee().toString();
    if (functionName.contains("query") || functionName.contains("exec") || functionName.contains("execute")) {
      checkSQLQueriesForOTP(functionCall);
    }
  }

  private void checkAssignment(AssignmentExpressionTree assignment) {
    // Check for $_SESSION['otp'] = $value type patterns
    ExpressionTree variable = assignment.variable();
    
    if (variable.is(Kind.ARRAY_ACCESS)) {
      String varText = variable.toString().toLowerCase();
      if (varText.contains("_session") && OTP_VAR_PATTERN.matcher(varText).find()) {
        // Direct session storage without hashing is being used
        context().newIssue(this, variable,
            "OTP should not be stored in plaintext in session variables. Use hashing with a salt.");
      }
    }
  }
  
  private void checkArrayInitializer(ArrayInitializerTree arrayInitializer) {
    // Check for ['otp' => $value] patterns in array initializers
    for (ArrayPairTree pair : arrayInitializer.arrayPairs()) {
      if (pair.key() != null && pair.key().is(Kind.REGULAR_STRING_LITERAL)) {
        String key = ((LiteralTree) pair.key()).value().toLowerCase();
        // Remove quotes from the key
        key = key.replaceAll("['\"]", "");
        
        if (OTP_VAR_PATTERN.matcher(key).find()) {
          // Array has an 'otp' key with a value, check if the value is hashed
          ExpressionTree value = pair.value();
          if (value.is(Kind.VARIABLE_IDENTIFIER)) {
            // If it's just a variable like $otp, it's likely plaintext
            context().newIssue(this, pair,
                "OTP should not be stored in plaintext. Use a secure hashing function with a salt.");
          } else if (!isFunctionCallWithHash(value)) {
            // If it's not a hash function call, it's likely plaintext
            context().newIssue(this, pair,
                "Potential plaintext OTP detected in array. Use a secure hashing function.");
          }
        }
      }
    }
  }

  private boolean isFunctionCallWithHash(ExpressionTree expression) {
    if (expression.is(Kind.FUNCTION_CALL)) {
      FunctionCallTree functionCall = (FunctionCallTree) expression;
      String functionName = functionCall.callee().toString().toLowerCase();
      return functionName.contains("hash") || 
             functionName.contains("bcrypt") ||
             functionName.contains("password_hash") || 
             functionName.contains("encrypt") || 
             functionName.contains("make");
    }
    return false;
  }
  
  private void checkArgumentsForPlaintextOTP(FunctionCallTree functionCall, String methodName) {
    if (functionCall.arguments().isEmpty()) {
      return;
    }
    
    // For create/insert methods, the first argument is usually an array with column => value pairs
    ExpressionTree firstArg = functionCall.arguments().get(0);
    
    if (firstArg.is(Kind.ARRAY_INITIALIZER_FUNCTION) || firstArg.is(Kind.ARRAY_INITIALIZER_BRACKET)) {
      ArrayInitializerTree arrayInit = (ArrayInitializerTree) firstArg;
      
      for (ArrayPairTree pair : arrayInit.arrayPairs()) {
        if (pair.key() != null && pair.key().is(Kind.REGULAR_STRING_LITERAL)) {
          String key = ((LiteralTree) pair.key()).value().toLowerCase();
          key = key.replaceAll("['\"]", ""); // Remove quotes
          
          if (OTP_VAR_PATTERN.matcher(key).find()) {
            ExpressionTree value = pair.value();
            
            // Check if the value is properly hashed or not
            if (value.is(Kind.VARIABLE_IDENTIFIER) || 
                value.is(Kind.REGULAR_STRING_LITERAL) || 
                value.is(Kind.NUMERIC_LITERAL) ||
                value.is(Kind.BOOLEAN_LITERAL) ||
                value.is(Kind.NULL_LITERAL)) {
              context().newIssue(this, pair,
                  "OTP should not be stored in plaintext when using " + methodName + "(). Use a secure hashing function.");
            } else if (!isFunctionCallWithHash(value)) {
              context().newIssue(this, pair,
                  "Potential plaintext OTP detected in " + methodName + "() call. Use a secure hashing function.");
            }
          }
        }
      }
    }
  }
  
  private void checkLogStatementsForOTP(FunctionCallTree functionCall) {
    // Check for OTP variables in log statements
    for (ExpressionTree argument : functionCall.arguments()) {
      String argText = argument.toString().toLowerCase();
      if (OTP_VAR_PATTERN.matcher(argText).find()) {
        context().newIssue(this, argument,
            "OTP values should never be logged in plaintext. This could expose sensitive authentication codes in logs.");
      }
    }
  }
  
  private void checkSQLQueriesForOTP(FunctionCallTree functionCall) {
    // Check for SQL queries with OTP
    for (ExpressionTree argument : functionCall.arguments()) {
      if (argument.is(Kind.REGULAR_STRING_LITERAL) || argument.is(Kind.CONCATENATION)) {
        String argText = argument.toString().toLowerCase();
        
        // Look for SQL INSERT/UPDATE with OTP column references
        if ((argText.contains("insert into") || argText.contains("update")) && 
            (argText.contains("otp") || argText.contains("one time") || argText.contains("verification code"))) {
          
          // Check if it's using a hash function
          if (!argText.contains("hash") && !argText.contains("password_hash") && !argText.contains("bcrypt")) {
            context().newIssue(this, argument,
                "SQL query appears to store OTP in plaintext. OTP values should be securely hashed before storage.");
          }
        }
      }
    }
  }
}