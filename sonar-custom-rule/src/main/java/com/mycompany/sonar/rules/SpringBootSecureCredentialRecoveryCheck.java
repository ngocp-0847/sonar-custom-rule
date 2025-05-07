package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.check.Priority;
import org.sonar.plugins.java.api.JavaFileScanner;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.tree.*;
import org.sonar.plugins.java.api.semantic.Symbol;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.ArrayList;

@Rule(
  key = "SpringBootSecureCredentialRecovery",
  name = "Password recovery mechanisms must use secure methods like TOTP or other secure verification",
  priority = Priority.CRITICAL,
  tags = {"security", "spring-boot", "password-reset", "owasp-asvs"}
)
public class SpringBootSecureCredentialRecoveryCheck extends BaseTreeVisitor implements JavaFileScanner {

  private static final Logger LOGGER = LoggerFactory.getLogger(SpringBootSecureCredentialRecoveryCheck.class);
  private JavaFileScannerContext context;
  
  // Patterns for insecure password recovery mechanism detection
  private static final Pattern PASSWORD_RECOVERY_PATTERN = Pattern.compile(
      "(?i)reset(\\s*|_)password|forgot(\\s*|_)password|recover(\\s*|_)password|password(\\s*|_)recovery");
  
  // Patterns for security questions - often used as an insecure recovery mechanism
  private static final Pattern SECURITY_QUESTIONS_PATTERN = Pattern.compile(
      "(?i)security(\\s*|_)question|secret(\\s*|_)question|mother(\\s*|_)maiden|birth(\\s*|_)place|first(\\s*|_)pet");
  
  // Methods/classes that might indicate email-only password reset
  private static final List<String> SIMPLE_EMAIL_RESET_INDICATORS = Arrays.asList(
      "sendpasswordresetemail", 
      "forgotpasswordemail", 
      "resetlink", 
      "passwordresettoken",
      "generateresettoken"
  );
  
  // Patterns for secure recovery mechanisms
  private static final Pattern SECURE_MECHANISM_PATTERN = Pattern.compile(
      "(?i)twofactor|2fa|mfa|multifactor|otp|totp|hotp|authenticator|timebased|timebase");
  
  // Classes that indicate secure implementations
  private static final List<String> SECURE_LIBRARIES = Arrays.asList(
      "totp", 
      "googleauthenticator", 
      "totputils", 
      "otputil", 
      "twofactorauthentication",
      "webauthn",
      "pushnotification",
      "timebased",
      "speakeasy"
  );

  @Override
  public void scanFile(JavaFileScannerContext context) {
    this.context = context;
    scan(context.getTree());
  }

  @Override
  public void visitClass(ClassTree tree) {
    // Check if this class is related to password recovery
    String className = tree.simpleName().name().toLowerCase();
    if (isPasswordRecoveryClass(className)) {
      checkSecurePasswordRecovery(tree);
    }
    
    // Continue visiting the class
    super.visitClass(tree);
  }
  
  @Override
  public void visitMethod(MethodTree tree) {
    // Check if this method is related to password recovery
    String methodName = tree.simpleName().name().toLowerCase();
    System.out.println("visitMethod: " + methodName);
    if (isPasswordRecoveryMethod(methodName)) {
      checkSecurePasswordRecoveryMethod(tree);
    }

    // Continue visiting the method
    super.visitMethod(tree);
  }
  
  @Override
  public void visitMethodInvocation(MethodInvocationTree tree) {
    // Check for calls to insecure password reset methods
    if (tree.methodSelect().is(Tree.Kind.MEMBER_SELECT)) {
      MemberSelectExpressionTree memberSelect = (MemberSelectExpressionTree) tree.methodSelect();
      String methodName = memberSelect.identifier().name().toLowerCase();
      String expressionText = memberSelect.expression().toString().toLowerCase();
      
      // Check if this is a method call related to password recovery
      if (isPasswordRecoveryMethod(methodName) || 
          (expressionText.contains("email") && 
           (methodName.contains("send") || methodName.contains("reset")))) {
        
        // Check if it seems to be using just email for reset without additional verification
        boolean hasSecureRecovery = hasSecureRecoveryMechanism(tree);
        if (!hasSecureRecovery && !isInSecureContext(tree)) {
          reportIssue(tree, "This password recovery mechanism appears to use only email-based reset without additional security factors. " +
                      "OWASP ASVS v2.5.6 requires secure recovery mechanisms like TOTP, soft tokens, mobile push, or offline verification.");
        }
      }
    }
    
    super.visitMethodInvocation(tree);
  }
  
  private boolean isPasswordRecoveryClass(String className) {
    return PASSWORD_RECOVERY_PATTERN.matcher(className).find() ||
           className.contains("forgotpassword") ||
           className.contains("resetpassword") ||
           className.contains("passwordreset") ||
           className.contains("accountrecovery");
  }
  
  private boolean isPasswordRecoveryMethod(String methodName) {
    return PASSWORD_RECOVERY_PATTERN.matcher(methodName).find() ||
           methodName.contains("forgotpassword") ||
           methodName.contains("resetpassword") ||
           methodName.contains("sendrecovery") ||
           methodName.contains("generatetoken") && 
           (methodName.contains("reset") || methodName.contains("recovery"));
  }
  
  private void checkSecurePasswordRecovery(ClassTree tree) {
    boolean hasSecureMechanism = false;
    boolean hasInsecureMechanism = false;
    
    // Check for indicators of secure and insecure recovery mechanisms
    List<Tree> members = tree.members();
    for (Tree member : members) {
      if (member.is(Tree.Kind.VARIABLE)) {
        VariableTree variable = (VariableTree) member;
        String varName = variable.simpleName().name().toLowerCase();
        
        // Check if this variable indicates a secure mechanism
        if (SECURE_MECHANISM_PATTERN.matcher(varName).find()) {
          hasSecureMechanism = true;
        }
        
        // Check if this variable indicates security questions (insecure mechanism)
        if (SECURITY_QUESTIONS_PATTERN.matcher(varName).find()) {
          hasInsecureMechanism = true;
        }
      }
    }
    
    // If we found indications of password recovery but no secure mechanisms
    if (!hasSecureMechanism && hasInsecureMechanism) {
      reportIssue(tree, "This password recovery implementation appears to use security questions or other insecure methods. " +
                   "OWASP ASVS v2.5.6 requires secure recovery mechanisms like TOTP, soft tokens, mobile push, or offline verification.");
    }
  }
  
  private void checkSecurePasswordRecoveryMethod(MethodTree tree) {
    // Check if method contains secure recovery implementations
    boolean hasSecureImplementation = false;
    
    // Check method body for signs of secure implementations
    BlockTree body = tree.block();
    if (body != null) {
      for (StatementTree statement : body.body()) {
        if (containsSecureMechanism(statement)) {
          hasSecureImplementation = true;
          break;
        }
      }
    }
    
    // Check dependencies and imports for secure libraries
    if (!hasSecureImplementation && !isInSecureContext(tree)) {
      // Log method name for potential false positive analysis
      String methodName = tree.simpleName().name();
      
      // Generate appropriate message based on context
      if (isSimpleEmailResetMethod(methodName)) {
        reportIssue(tree, "This password reset method appears to only send an email with reset link without additional verification. " +
                     "OWASP ASVS v2.5.6 requires secure recovery mechanisms like TOTP, soft tokens, mobile push, or offline verification.");
      } else {
        reportIssue(tree, "This password recovery method doesn't appear to implement recommended secure recovery mechanisms. " +
                     "OWASP ASVS v2.5.6 requires secure recovery mechanisms like TOTP, soft tokens, mobile push, or offline verification.");
      }
    }
  }
  
  private boolean isSimpleEmailResetMethod(String methodName) {
    methodName = methodName.toLowerCase();
    for (String indicator : SIMPLE_EMAIL_RESET_INDICATORS) {
      if (methodName.contains(indicator.toLowerCase())) {
        return true;
      }
    }
    return false;
  }
  
  private boolean containsSecureMechanism(Tree tree) {
    // Simple string-based search for secure mechanisms
    String treeString = tree.toString().toLowerCase();
    // Check for TOTP or other secure implementations
    if (SECURE_MECHANISM_PATTERN.matcher(treeString).find()) {
      return true;
    }
    
    // Check for known secure libraries
    for (String library : SECURE_LIBRARIES) {
      if (treeString.contains(library)) {
        return true;
      }
    }
    
    return false;
  }
  
  private boolean hasSecureRecoveryMechanism(MethodInvocationTree tree) {
    // Check arguments and context for secure mechanisms
    for (ExpressionTree arg : tree.arguments()) {
      if (containsSecureMechanism(arg)) {
        return true;
      }
    }
    
    // Check the surrounding method
    Tree parent = getEnclosingMethod(tree);
    if (parent != null && parent.is(Tree.Kind.METHOD)) {
      MethodTree method = (MethodTree) parent;
      BlockTree body = method.block();
      
      if (body != null) {
        for (StatementTree statement : body.body()) {
          if (containsSecureMechanism(statement)) {
            return true;
          }
        }
      }
    }
    
    return false;
  }
  
  private boolean isInSecureContext(Tree tree) {
    // Check if this tree is within a secure context
    // For example, if the class implements or uses secure mechanisms
    
    Tree classTree = getEnclosingClass(tree);
    if (classTree != null && classTree.is(Tree.Kind.CLASS)) {
      ClassTree enclosingClass = (ClassTree) classTree;
      String className = enclosingClass.simpleName().name().toLowerCase();
      
      // Check class name for secure indicators
      if (SECURE_MECHANISM_PATTERN.matcher(className).find()) {
        return true;
      }
      
      // Check for secure libraries in class members
      for (Tree member : enclosingClass.members()) {
        if (containsSecureMechanism(member)) {
          return true;
        }
      }
    }
    
    return false;
  }
  
  private Tree getEnclosingMethod(Tree tree) {
    // Find the enclosing method of a tree node
    Tree parent = tree;
    while (parent != null && !parent.is(Tree.Kind.METHOD)) {
      parent = parent.parent();
    }
    return parent;
  }
  
  private Tree getEnclosingClass(Tree tree) {
    // Find the enclosing class of a tree node
    Tree parent = tree;
    while (parent != null && !parent.is(Tree.Kind.CLASS)) {
      parent = parent.parent();
    }
    return parent;
  }

  private void reportIssue(Tree tree, String message) {
    context.reportIssue(this, tree, message);
  }
}
