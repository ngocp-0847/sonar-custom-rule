# Lỗi: Sử Dụng Bộ Sinh Số Ngẫu Nhiên Không An Toàn

## Mô tả
Lỗi này xảy ra khi ứng dụng sử dụng các hàm sinh số ngẫu nhiên không an toàn về mặt mật mã (non-cryptographically secure) để tạo ra các giá trị quan trọng như mã token, ID phiên, mật khẩu tạm thời, hoặc thậm chí là khóa mã hóa. Các bộ sinh số ngẫu nhiên thông thường (`Math.random()`, `Random`, `rand()`) không đủ ngẫu nhiên để chống lại các cuộc tấn công dự đoán, cho phép kẻ tấn công có thể đoán trước được các giá trị được tạo ra.

## Ví dụ Lỗi

### 1. Sử dụng Math.random() để tạo token (JavaScript)

```javascript
// LỖI: Sử dụng Math.random() để tạo token
function generateInsecureToken(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  
  // LỖI: Math.random() không phải là CSPRNG
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    token += chars.charAt(randomIndex);
  }
  
  return token;
}

// Sử dụng token không an toàn cho phiên đăng nhập
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Xác thực người dùng...
  
  // Tạo phiên mới với token không an toàn
  const sessionToken = generateInsecureToken();
  
  // Lưu phiên
  sessions[sessionToken] = {
    userId: user.id,
    createdAt: new Date()
  };
  
  res.cookie('sessionToken', sessionToken, { httpOnly: true });
  res.json({ success: true });
});
```

### 2. Sử dụng Random không an toàn để tạo mật khẩu tạm thời (Java)

```java
public class InsecureRandomExample {
    
    // LỖI: Sử dụng java.util.Random thay vì SecureRandom
    private static final Random random = new Random();
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    // Tạo mật khẩu tạm thời không an toàn
    public static String generateTemporaryPassword(int length) {
        StringBuilder password = new StringBuilder();
        
        // LỖI: java.util.Random không an toàn về mặt mật mã
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(CHARS.length());
            password.append(CHARS.charAt(randomIndex));
        }
        
        return password.toString();
    }
    
    // Phương thức đặt lại mật khẩu
    public static void resetPassword(String email) {
        User user = userRepository.findByEmail(email);
        
        if (user != null) {
            // Tạo mật khẩu tạm thời không an toàn
            String tempPassword = generateTemporaryPassword(10);
            
            // Cập nhật mật khẩu và gửi email
            user.setPassword(hashPassword(tempPassword));
            userRepository.save(user);
            emailService.sendPasswordResetEmail(email, tempPassword);
        }
    }
}
```

### 3. Sử dụng rand() để tạo tên file ngẫu nhiên (PHP)

```php
<?php
// LỖI: Sử dụng hàm rand() để tạo tên file ngẫu nhiên
function generateRandomFilename($extension = 'jpg') {
    // LỖI: Sử dụng rand() không an toàn về mặt mật mã
    $randomNumber = rand(100000, 999999);
    $timestamp = time();
    
    return $timestamp . '_' . $randomNumber . '.' . $extension;
}

// Xử lý tải lên file
if ($_FILES['userFile']['error'] == 0) {
    $extension = pathinfo($_FILES['userFile']['name'], PATHINFO_EXTENSION);
    
    // Tạo tên file ngẫu nhiên không an toàn
    $filename = generateRandomFilename($extension);
    
    // Di chuyển file tải lên
    move_uploaded_file($_FILES['userFile']['tmp_name'], 'uploads/' . $filename);
    
    // Lưu thông tin file vào cơ sở dữ liệu
    saveFileInfo($userId, $filename);
    
    echo json_encode(['success' => true, 'filename' => $filename]);
}
?>
```

## Cách Khắc Phục

### 1. Sử dụng CSPRNG để tạo token (JavaScript)

```javascript
const crypto = require('crypto');

// FIX: Sử dụng crypto.randomBytes() để tạo token an toàn
function generateSecureToken(length = 32) {
  // Sử dụng crypto.randomBytes() - một CSPRNG
  return crypto.randomBytes(length)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
    .slice(0, length);
}

// Sử dụng token an toàn cho phiên đăng nhập
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Xác thực người dùng...
  
  // Tạo phiên mới với token an toàn
  const sessionToken = generateSecureToken();
  
  // Lưu phiên
  sessions[sessionToken] = {
    userId: user.id,
    createdAt: new Date()
  };
  
  // Thiết lập cookie với các tùy chọn bảo mật
  res.cookie('sessionToken', sessionToken, { 
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  
  res.json({ success: true });
});
```

### 2. Sử dụng SecureRandom để tạo mật khẩu tạm thời (Java)

```java
import java.security.SecureRandom;

public class SecureRandomExample {
    
    // FIX: Sử dụng SecureRandom thay vì Random
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    
    // Tạo mật khẩu tạm thời an toàn
    public static String generateSecureTemporaryPassword(int length) {
        StringBuilder password = new StringBuilder();
        
        // Sử dụng SecureRandom - CSPRNG được chấp nhận
        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(CHARS.length());
            password.append(CHARS.charAt(randomIndex));
        }
        
        return password.toString();
    }
    
    // Phương thức đặt lại mật khẩu
    public static void resetPassword(String email) {
        User user = userRepository.findByEmail(email);
        
        if (user != null) {
            // Tạo mật khẩu tạm thời an toàn
            String tempPassword = generateSecureTemporaryPassword(12);
            
            // Cập nhật mật khẩu và gửi email
            user.setPassword(hashPassword(tempPassword));
            user.setPasswordResetRequired(true);
            
            // Đặt thời gian hết hạn cho mật khẩu tạm thời
            user.setPasswordExpiryTime(LocalDateTime.now().plusHours(24));
            
            userRepository.save(user);
            emailService.sendPasswordResetEmail(email, tempPassword);
        }
    }
}
```

### 3. Sử dụng random_bytes để tạo tên file ngẫu nhiên (PHP)

```php
<?php
// FIX: Sử dụng random_bytes() để tạo tên file ngẫu nhiên
function generateSecureFilename($extension = 'jpg') {
    // Sử dụng random_bytes() - một CSPRNG
    $randomBytes = random_bytes(16);
    $randomString = bin2hex($randomBytes);
    $timestamp = time();
    
    return $timestamp . '_' . $randomString . '.' . $extension;
}

// Xử lý tải lên file
if ($_FILES['userFile']['error'] == 0) {
    $extension = pathinfo($_FILES['userFile']['name'], PATHINFO_EXTENSION);
    
    // Xác thực extension
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    if (!in_array(strtolower($extension), $allowedExtensions)) {
        echo json_encode(['success' => false, 'error' => 'Invalid file type']);
        exit;
    }
    
    // Tạo tên file ngẫu nhiên an toàn
    $filename = generateSecureFilename($extension);
    
    // Di chuyển file tải lên và thiết lập quyền
    move_uploaded_file($_FILES['userFile']['tmp_name'], 'uploads/' . $filename);
    chmod('uploads/' . $filename, 0644);
    
    // Lưu thông tin file vào cơ sở dữ liệu
    saveFileInfo($userId, $filename);
    
    echo json_encode(['success' => true, 'filename' => $filename]);
}
?>
```

## Phòng Ngừa

1. **Luôn sử dụng CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)**:
   - JavaScript: `crypto.randomBytes()`, `window.crypto.getRandomValues()`
   - Java: `java.security.SecureRandom`
   - PHP: `random_bytes()`, `openssl_random_pseudo_bytes()`
   - Python: `secrets` module, `os.urandom()`
   - C#: `System.Security.Cryptography.RandomNumberGenerator`

2. **Tránh sử dụng các hàm ngẫu nhiên thông thường**:
   - KHÔNG sử dụng `Math.random()` (JavaScript)
   - KHÔNG sử dụng `java.util.Random` (Java)
   - KHÔNG sử dụng `rand()` hoặc `mt_rand()` (PHP)
   - KHÔNG sử dụng `random.random()` (Python)

3. **Sử dụng đủ entropy (độ ngẫu nhiên)**:
   - Đảm bảo sử dụng đủ bytes ngẫu nhiên cho mục đích bảo mật
   - Tối thiểu 16 bytes (128 bits) cho token
   - Tối thiểu 32 bytes (256 bits) cho khóa mã hóa

4. **Xử lý thích hợp các giá trị ngẫu nhiên**:
   - Mã hóa các giá trị ngẫu nhiên một cách an toàn (base64, hex)
   - Không cắt bớt hoặc rút gọn giá trị ngẫu nhiên theo cách làm giảm tính ngẫu nhiên

5. **Kiểm tra nguồn entropy**:
   - Đảm bảo hệ điều hành có đủ entropy để tạo số ngẫu nhiên an toàn
   - Sử dụng các dịch vụ như `/dev/urandom` trên Unix/Linux

## Tác động của lỗi
Sử dụng bộ sinh số ngẫu nhiên không an toàn có thể dẫn đến:
1. Dự đoán được token phiên, cho phép tấn công chiếm đoạt phiên
2. Dự đoán được ID tài nguyên, cho phép truy cập trái phép
3. Khóa mã hóa yếu, làm giảm đáng kể độ an toàn của mã hóa
4. Dự đoán được mật khẩu tạm thời, cho phép tấn công vào tài khoản 