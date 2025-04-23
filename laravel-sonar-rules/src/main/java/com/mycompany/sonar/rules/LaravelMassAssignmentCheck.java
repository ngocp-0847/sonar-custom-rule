package com.mycompany.sonar.rules;

import org.sonar.check.Rule;
import org.sonar.check.Priority;
import org.sonar.plugins.php.api.visitors.PHPVisitorCheck;
import org.sonar.plugins.php.api.tree.Tree;
import org.sonar.plugins.php.api.tree.Tree.Kind;
import org.sonar.plugins.php.api.tree.expression.FunctionCallTree;
import org.sonar.plugins.php.api.tree.expression.MemberAccessTree;
import org.sonar.plugins.php.api.tree.expression.VariableIdentifierTree;
import org.sonar.plugins.php.api.tree.expression.ExpressionTree;
import org.sonar.plugins.php.api.tree.expression.LiteralTree;
import org.sonar.plugins.php.api.tree.declaration.ClassDeclarationTree;
import org.sonar.plugins.php.api.tree.declaration.ClassPropertyDeclarationTree;
import org.sonar.plugins.php.api.tree.expression.IdentifierTree;
import org.sonar.plugins.php.api.symbols.Symbol;
import org.sonar.plugins.php.api.visitors.PHPSubscriptionCheck;
import org.sonar.php.tree.symbols.SymbolTableImpl;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
// Add SLF4J imports
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Rule(
  key = "LaravelMassAssignment",
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
    // Kiểm tra xem đây có phải là lời gọi hàm không
    if (!functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) &&
        !functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      return;
    }

    // Sửa: Thêm log để kiểm tra loại của cây
    LOGGER.info("Function call detected at line {}: {}", functionCall);

    
    // Kiểm tra xem đây có phải là lời gọi Model::create(), $model->fill() hoặc $model->update() không
    if (functionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS) || 
        functionCall.callee().is(Kind.CLASS_MEMBER_ACCESS)) {
      
      MemberAccessTree memberAccess = (MemberAccessTree) functionCall.callee();
      // Sửa: Lấy tên phương thức từ member access
      String methodName = ((IdentifierTree)memberAccess.member()).text();
      LOGGER.info("Method name: {}", methodName);
      
      // Kiểm tra xem phương thức có nằm trong danh sách các phương thức không an toàn hay không
      if (UNSAFE_METHODS.contains(methodName)) {
        LOGGER.info("Found unsafe method: {} at line {}", methodName);
        
        // Kiểm tra xem tham số đầu tiên của phương thức là gì
        if (!functionCall.arguments().isEmpty()) {
          ExpressionTree firstArgument = functionCall.arguments().get(0);
          LOGGER.info("First argument type: {}", firstArgument.getClass().getSimpleName());
          
          // Kiểm tra xem tham số đầu tiên có phải là $request->all() hoặc $request->input() không
          if (firstArgument.is(Kind.FUNCTION_CALL)) {
            FunctionCallTree argFunctionCall = (FunctionCallTree) firstArgument;
            LOGGER.info("First argument is a function call: {}", argFunctionCall.toString().replaceAll("\\s+", " ").trim());
            
            if (argFunctionCall.callee().is(Kind.OBJECT_MEMBER_ACCESS)) {
              MemberAccessTree argMemberAccess = (MemberAccessTree) argFunctionCall.callee();
              // Sửa: Lấy tên phương thức từ member access
              String argMethodName = ((IdentifierTree)argMemberAccess.member()).text();
              LOGGER.info("Argument method name: {}", argMethodName);
              
              if (UNSAFE_REQUEST_METHODS.contains(argMethodName)) {
                // Đây là lỗ hổng mass assignment
                context().newIssue(this, tree, 
                  "Unsafe mass assignment detected: Using " + methodName + "() with " + 
                  argMethodName + "() can lead to mass assignment vulnerabilities. " + 
                  "Make sure $fillable or $guarded is properly set in the model.");
              }
            }
          }
          
          // Kiểm tra cho trường hợp $request->all()
          if (firstArgument.is(Kind.VARIABLE_IDENTIFIER)) {
            // Phát hiện các biến trực tiếp như $request hay $input
            VariableIdentifierTree varIdentifier = (VariableIdentifierTree) firstArgument;
            String varName = varIdentifier.text();
            LOGGER.info("First argument is a variable: {}", varName);
            
            if (varName.contains("request") || varName.contains("input")) {

              context().newIssue(this, tree,
                "Potential unsafe mass assignment detected: Using " + methodName + "() with " + 
                varName + " can lead to mass assignment vulnerabilities. " +
                "Make sure $fillable or $guarded is properly set in the model.");
            }
          }
        } else {
          LOGGER.info("No arguments found for unsafe method call at line {}");
        }
      }
    }
  }
}
