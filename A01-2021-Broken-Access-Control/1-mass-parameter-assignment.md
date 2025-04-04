# Lỗi: Mass Parameter Assignment (Mass Assignment)

## Mô tả
https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

Mass Parameter Assignment (còn gọi là Object Injection hoặc Autobinding) là lỗ hổng bảo mật xảy ra khi ứng dụng tự động gán dữ liệu được gửi từ người dùng vào các đối tượng hoặc thuộc tính mà không có kiểm tra phù hợp. Điều này có thể cho phép kẻ tấn công thay đổi các thuộc tính không nên được thay đổi.

## Ví dụ lỗi trong Express.js (Node.js)

```javascript
// Mô hình User
const User = {
  username: String,
  email: String,
  isAdmin: Boolean
}

// Route cập nhật thông tin người dùng - CÓ LỖI
app.post('/update-user', async (req, res) => {
  try {
    // LỖI: Lấy toàn bộ thông tin từ request body và cập nhật vào DB
    const updatedUser = await User.findByIdAndUpdate(
      req.session.userId,
      req.body,  // Nguy hiểm: Gán toàn bộ dữ liệu từ người dùng
      {new: true}
    );
    
    res.json({success: true, user: updatedUser});
  } catch (err) {
    res.status(500).json({error: 'Lỗi cập nhật'});
  }
});
```

Trong ví dụ trên, kẻ tấn công có thể gửi dữ liệu như sau để tự gán quyền admin:

```
POST /update-user HTTP/1.1
Content-Type: application/json

{
  "username": "user1",
  "email": "user1@example.com",
  "isAdmin": true
}
```

## Cách khắc phục

### 1. Đánh dấu các trường nhạy cảm là private

```javascript
// Mô hình User với trường isAdmin được bảo vệ
const userSchema = new Schema({
  username: String,
  email: String,
  isAdmin: {
    type: Boolean,
    default: false,
    private: true // Đánh dấu là private trong một số framework
  }
});
```

### 2. Hạn chế cập nhật hàng loạt với danh sách cho phép (Allowlist)

```javascript
// Sửa lỗi: Sử dụng allowlist để chỉ cho phép cập nhật các trường an toàn
app.post('/update-user', async (req, res) => {
  try {
    // Chỉ chọn các trường được phép cập nhật
    const allowedFields = ['username', 'email', 'fullName', 'bio'];
    const updateData = {};
    
    // Lọc dữ liệu đầu vào, chỉ giữ các trường được phép
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updateData[field] = req.body[field];
      }
    });
    
    // Cập nhật chỉ với các trường đã được lọc
    const updatedUser = await User.findByIdAndUpdate(
      req.session.userId,
      updateData,
      {new: true}
    );
    
    res.json({success: true, user: updatedUser});
  } catch (err) {
    res.status(500).json({error: 'Lỗi cập nhật'});
  }
});
```

### 3. Trong Spring Boot (Java)

Sử dụng annotation để giới hạn các thuộc tính có thể gán:

```java
public class UserDTO {
    private String username;
    private String email;
    
    // Không có trường isAdmin ở đây
    
    // Getters and setters
}

@RestController
public class UserController {
    
    @PostMapping("/update-user")
    public ResponseEntity<?> updateUser(@RequestBody UserDTO userDTO, Authentication auth) {
        User user = userService.findByUsername(auth.getName());
        
        // Chỉ cập nhật các thuộc tính từ DTO
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        
        // isAdmin không thể bị cập nhật qua API này
        
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }
}
```

## Phòng ngừa

1. Luôn xác định rõ các trường có thể được cập nhật
2. Sử dụng DTO (Data Transfer Objects) riêng cho từng API
3. Không bao giờ tin tưởng dữ liệu từ người dùng mà không kiểm tra
4. Thực hiện kiểm tra quyền hạn trước khi cập nhật dữ liệu
5. Kiểm soát nghiêm ngặt các thuộc tính nhạy cảm như quyền admin, role, v.v. 