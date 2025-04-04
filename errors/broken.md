A01:2021 - Broken Access Control
: 5.1.2	
: Xác minh rằng framework bảo vệ chống lại cuộc tấn công Mass Parameter Assignment	"Đánh dấu các trường nhạy cảm là private.
Hạn chế cập nhật hàng loạt đối với các trường quan trọng.
Sử dụng danh sách cho phép (Allow List) để kiểm soát các trường có thể cập nhật."

### Lỗi **A01:2021 - Broken Access Control** (Kiểm soát truy cập bị phá vỡ)

Đây là lỗi bảo mật đứng đầu trong danh sách OWASP Top 10 năm 2021. Lỗi này xảy ra khi các cơ chế kiểm soát truy cập không được thực hiện đúng cách, cho phép người dùng vượt qua các hạn chế quyền truy cập và thực hiện các hành động trái phép.

---

## **5.1.2 - Mass Parameter Assignment**
Lỗi này liên quan đến việc gán hàng loạt tham số đầu vào mà không có kiểm soát, dẫn đến nguy cơ truy cập hoặc thay đổi dữ liệu trái phép. Điều này đặc biệt nghiêm trọng trong các ứng dụng web sử dụng các framework hỗ trợ binding dữ liệu tự động từ request vào model.

### **Ví dụ về lỗ hổng**
#### **Tình huống**
Một ứng dụng web cho phép người dùng cập nhật thông tin cá nhân bằng cách gửi một request như sau:

```json
{
    "username": "user123",
    "email": "user@example.com",
    "role": "admin"
}
```

Nếu hệ thống sử dụng binding tự động mà không có kiểm soát, hacker có thể gửi request với trường `"role": "admin"`, nâng cấp tài khoản của họ lên quyền admin một cách trái phép.

---

## **Cách bảo vệ**
### **1. Đánh dấu các trường nhạy cảm là `private`**
Trong các framework như Laravel, Django, hoặc Spring Boot, có thể đánh dấu các trường nhạy cảm như `role`, `is_admin`, `balance` là **private hoặc protected**, để tránh bị cập nhật ngoài ý muốn.

#### **Ví dụ trong Laravel**
```php
protected $guarded = ['role', 'is_admin']; // Không cho phép cập nhật các trường này
```

---

### **2. Hạn chế cập nhật hàng loạt đối với các trường quan trọng**
Sử dụng `fillable` thay vì `guarded` để chỉ định rõ những trường nào được phép cập nhật.

#### **Ví dụ trong Laravel**
```php
protected $fillable = ['username', 'email']; // Chỉ cho phép cập nhật 2 trường này
```

---

### **3. Sử dụng Allow List để kiểm soát dữ liệu có thể cập nhật**
Thay vì cho phép cập nhật tất cả các thuộc tính, hãy chỉ định danh sách các trường hợp cho phép.

#### **Ví dụ trong Node.js (Express)**
```js
const allowedFields = ["username", "email"];
const updateData = {};
for (let field of allowedFields) {
    if (req.body[field]) {
        updateData[field] = req.body[field];
    }
}
User.update(updateData, { where: { id: req.user.id } });
```
🔹 **Lợi ích:** Chỉ cập nhật những trường được cho phép, ngăn chặn hacker sửa đổi dữ liệu nhạy cảm như quyền truy cập (`role`).

---

## **Tổng kết**
- **Mass Parameter Assignment** xảy ra khi ứng dụng tự động ánh xạ toàn bộ dữ liệu từ request vào object mà không kiểm soát.
- **Giải pháp:** 
  - Đánh dấu các trường quan trọng là `private/protected`.
  - Sử dụng danh sách chỉ định (`fillable`, `allowedFields`).
  - Kiểm tra và xác thực dữ liệu đầu vào trước khi cập nhật.

👉 **Lỗi này phổ biến trong các framework có hỗ trợ binding tự động như Laravel, Django, Spring Boot, Rails,... nên cần đặc biệt lưu ý khi xử lý dữ liệu đầu vào!** 🚀