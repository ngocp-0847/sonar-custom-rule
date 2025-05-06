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
import org.sonar.plugins.php.api.tree.expression.AssignmentExpressionTree;
import org.sonar.plugins.php.api.tree.expression.IdentifierTree;
import org.sonar.plugins.php.api.tree.statement.ExpressionStatementTree;
import org.sonar.plugins.php.api.visitors.PHPSubscriptionCheck;
import org.sonar.plugins.php.api.visitors.CheckContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Rule(
  key = "UnsafeSVGContent",
  name = "User-supplied SVG content must be sanitized to prevent XSS",
  priority = Priority.CRITICAL,
  tags = {"security", "xss", "svg", "owasp-a3"}
)
public class UnsafeSVGContentCheck extends PHPSubscriptionCheck {

  private static final Logger LOGGER = LoggerFactory.getLogger(UnsafeSVGContentCheck.class);
  
  // Patterns to identify SVG content
  private static final Pattern SVG_PATTERN = Pattern.compile("(?i)<\\s*svg|\\bsvg\\b|image\\/svg\\+xml|\\.(svg)");
  
  // Patterns for dangerous SVG elements and attributes
  private static final Pattern SVG_DANGEROUS_ELEMENTS = Pattern.compile("(?i)<\\s*script|<\\s*foreignObject|<\\s*use\\s+xlink:href|<\\s*handler|<\\s*event");
  
  // Laravel functions/methods that render content without escaping
  private static final List<String> UNSAFE_OUTPUT_METHODS = Arrays.asList(
    "html", "rawSvg", "raw", "unescape", "dangerouslySetInnerHTML", "innerHTML"
  );
  
  // JS frameworks methods commonly used for rendering
  private static final List<String> JS_RENDER_METHODS = Arrays.asList(
    "render", "dangerouslySetInnerHTML", "innerHTML"
  );

  // Safe sanitization libraries/functions
  private static final List<String> SANITIZATION_METHODS = Arrays.asList(
    "sanitize", "sanitizeSvg", "DOMPurify", "purify", "clean", "escape", "htmlspecialchars", "strip_tags"
  );

  @Override
  public List<Kind> nodesToVisit() {
    return Arrays.asList(
        Kind.FUNCTION_CALL,           // For function calls
        Kind.ASSIGNMENT,              // For assignments
        Kind.INLINE_HTML,             // For inline HTML in PHP
        Kind.ECHO_TAG_STATEMENT       // For echo statements
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
      case INLINE_HTML:
        checkInlineHTML(tree);
        break;
      case ECHO_TAG_STATEMENT:
        checkEchoStatement(tree);
        break;
      default:
        // Not interested in other tree types
        break;
    }
  }

  private void checkFunctionCall(FunctionCallTree functionCall) {
    String functionText = functionCall.toString().toLowerCase();
    
    // Skip if this is a sanitization function
    for (String safeMethod : SANITIZATION_METHODS) {
      if (functionText.contains(safeMethod.toLowerCase())) {
        return;
      }
    }
    
    // Check if this is an unsafe method call that might output SVG
    if (functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) || 
        functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      
      MemberAccessTree memberAccess = (MemberAccessTree) functionCall.callee();
      String methodName = ((IdentifierTree) memberAccess.member()).text().toLowerCase();
      
      if (UNSAFE_OUTPUT_METHODS.contains(methodName) || JS_RENDER_METHODS.contains(methodName)) {
        // Check arguments for SVG content
        for (ExpressionTree argument : functionCall.arguments()) {
          String argText = argument.toString().toLowerCase();
          
          // Check if argument contains SVG references
          Matcher svgMatcher = SVG_PATTERN.matcher(argText);
          if (svgMatcher.find()) {
            // Check for dangerous SVG elements
            if (SVG_DANGEROUS_ELEMENTS.matcher(argText).find()) {
              context().newIssue(this, argument, 
                  "Potentially unsafe SVG content with script/foreignObject elements detected. Sanitize SVG before rendering.");
            } else {
              // Even without explicit dangerous elements, user-supplied SVG should be sanitized
              if (!functionText.contains("sanitize") && !functionText.contains("dompurify")) {
                context().newIssue(this, argument,
                    "User-supplied SVG content should be sanitized before rendering to prevent XSS attacks.");
              }
            }
          }
          
          // Check for user-input variables passed to unsafe methods
          if (argText.contains("$_") || argText.contains("request") || argText.contains("input") || 
              argText.contains("props") || argText.contains("param")) {
            context().newIssue(this, argument,
                "User input passed to " + methodName + "() could contain unsafe SVG content. Use an SVG sanitizer library.");
          }
        }
      }
    }
    
    // For React components, check for dangerouslySetInnerHTML use with SVG
    if (functionText.contains("dangerouslysetinnerhtml")) {
      checkForUnsafeSVGInFunction(functionCall);
    }
  }

  private void checkAssignment(AssignmentExpressionTree assignment) {
    String varName = assignment.variable().toString().toLowerCase();
    String valueText = assignment.value().toString().toLowerCase();
    
    // Check if assignment is to innerHTML-like properties
    if (varName.contains("innerhtml") || varName.contains("html") || varName.contains("svg")) {
      // Check if value might contain SVG
      if (SVG_PATTERN.matcher(valueText).find()) {
        // Check if proper sanitization is used
        boolean isSanitized = false;
        
        for (String safeMethod : SANITIZATION_METHODS) {
          if (valueText.contains(safeMethod.toLowerCase())) {
            isSanitized = true;
            break;
          }
        }
        
        if (!isSanitized) {
          context().newIssue(this, assignment,
              "Assignment to " + varName + " contains SVG content without proper sanitization. Use a sanitizer library.");
        }
      }
      
      // Check if value comes directly from user input
      if (valueText.contains("$_") || valueText.contains("request") || valueText.contains("->input(") || 
          valueText.contains("props") || valueText.contains("event.target")) {
        context().newIssue(this, assignment,
            "Assignment to " + varName + " with user input could contain unsafe SVG. Use DOMPurify or other sanitizer.");
      }
    }
  }
  
  private void checkInlineHTML(Tree htmlTree) {
    String htmlContent = htmlTree.toString().toLowerCase();
    
    // Check if inline HTML contains SVG elements
    if (htmlContent.contains("<svg") || htmlContent.contains("image/svg+xml")) {
      // Check for dynamic content insertion within SVG 
      if (htmlContent.contains("<?php") || htmlContent.contains("{{") || htmlContent.contains("{")) {
        
        // Check if there are dangerous SVG elements
        if (SVG_DANGEROUS_ELEMENTS.matcher(htmlContent).find()) {
          context().newIssue(this, htmlTree,
              "Inline SVG with dynamic content contains potentially dangerous elements (script/foreignObject). Sanitize user input.");
        } else {
          context().newIssue(this, htmlTree,
              "Dynamic content in SVG should be properly sanitized to prevent XSS attacks.");
        }
      }
    }
  }
  
  private void checkEchoStatement(Tree echoTree) {
    String echoContent = echoTree.toString().toLowerCase();
    
    // Check if echo statement might output SVG content
    if (SVG_PATTERN.matcher(echoContent).find()) {
      // Check if content is properly sanitized
      boolean isSanitized = false;
      
      for (String safeMethod : SANITIZATION_METHODS) {
        if (echoContent.contains(safeMethod.toLowerCase())) {
          isSanitized = true;
          break;
        }
      }
      
      if (!isSanitized) {
        context().newIssue(this, echoTree,
            "Echo statement may output unsanitized SVG content. Use htmlspecialchars() or a dedicated SVG sanitizer.");
      }
    }
  }
  
  private void checkForUnsafeSVGInFunction(FunctionCallTree functionCall) {
    String functionText = functionCall.toString().toLowerCase();
    
    // Check if function call includes SVG content
    if (SVG_PATTERN.matcher(functionText).find()) {
      boolean isSanitized = false;
      
      for (String safeMethod : SANITIZATION_METHODS) {
        if (functionText.contains(safeMethod.toLowerCase())) {
          isSanitized = true;
          break;
        }
      }
      
      if (!isSanitized) {
        context().newIssue(this, functionCall,
            "Function may output unsanitized SVG content. Use DOMPurify.sanitize() or a dedicated SVG sanitizer.");
      }
    }
  }
}