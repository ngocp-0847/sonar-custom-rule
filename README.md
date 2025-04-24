# Dự Án tạo custom rules cho SonarQube

Dự án này được tạo ra để kiểm tra và nghiên cứu các tính năng của SonarSource (SonarQube) trong việc phát hiện các lỗi bảo mật và chất lượng mã nguồn.

Cách tạo custom rules cho SonarQube để tạo thêm lỗi check mã nguồn cho SonarQube.

## Mục Tiêu

- Kiểm tra khả năng phát hiện lỗi bảo mật của SonarQube với các mẫu mã nguồn khác nhau.
- Hiểu rõ cách SonarQube phân tích và báo cáo các vấn đề bảo mật
- Cách custom rule và tạo ra các rule phù hợp với dự án của bạn.

## Hướng Dẫn Sử Dụng

### Chạy SonarQube bằng Docker

```bash
docker-compose up -d sonarqube
```

Sau khi khởi động, truy cập SonarQube tại địa chỉ: http://localhost:9000  
(Thông tin đăng nhập mặc định: admin/admin)

### Chạy phân tích mã nguồn

Hoặc sử dụng Docker Compose để chạy trình quét:

```bash
docker-compose up sonar-scanner
```

# Cách tạo thêm custom rule.
- Tạo một file Java mới trong thư mục `src/main/java/com/sonarsource/customrules` với tên `CustomRule.java`.
- Trong file này, bạn sẽ định nghĩa các quy tắc tùy chỉnh của mình bằng cách mở rộng các lớp và giao diện có sẵn trong SonarQube API.
- Ví dụ, bạn có thể tạo một quy tắc kiểm tra xem một biến có được khởi tạo hay không.

```java
package com.sonarsource.customrules;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.Tree;

@Rule(key = "CustomRule")
public class CustomRule extends IssuableSubscriptionVisitor {

  @Override
  public List<Tree.Kind> nodesToVisit() {
    return Collections.singletonList(Tree.Kind.METHOD_INVOCATION);
  }

  @Override
  public void visitNode(Tree tree) {
    MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;

    if (methodInvocationTree.symbol().name().equals("execute")) {
      reportIssue(methodInvocationTree, "Avoid using 'execute' method directly.");
    }
  }
}
```

- Sau khi đã tạo xong custom rule, bạn cần biên dịch lại plugin và khởi động lại SonarQube để áp dụng các thay đổi.

Chay script sau để rebuild lại plugin và active trên server sonarqube

```bash
./rebuild.sh
```

- Vào page sau để active rule http://localhost:9000/coding_rules?selected=css%3AS4655
- Chọn rule bạn đã tạo và nhấn vào nút "Activate" để kích hoạt nó.
- Sau khi kích hoạt rule, bạn cần phải cấu hình lại Quality Profile để áp dụng cho project.


## Kết Quả

Sau khi phân tích hoàn tất, bạn có thể xem kết quả và các vấn đề phát hiện được trong giao diện web của SonarQube.


![SonarQube Analysis Result](./demo-sonarquebe.png)

