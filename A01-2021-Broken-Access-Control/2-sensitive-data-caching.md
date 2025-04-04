# Lỗi: Lưu Trữ Dữ Liệu Nhạy Cảm Trong Bộ Nhớ Cache

## Mô tả
- https://cwe.mitre.org/data/definitions/524.html

Lỗi này xảy ra khi ứng dụng lưu trữ dữ liệu nhạy cảm (mật khẩu, thông tin thanh toán, dữ liệu cá nhân) trong các bộ nhớ cache như load balancers, CDN, application caches mà không có biện pháp bảo vệ phù hợp. Nếu bộ nhớ cache bị tấn công hoặc truy cập trái phép, dữ liệu nhạy cảm có thể bị rò rỉ.

## Ví dụ lỗi

### 1. Lưu trữ dữ liệu nhạy cảm trong Response Cache (Java Spring)

```java
@RestController
public class UserController {
    
    // LỖI: API trả về thông tin nhạy cảm và cho phép cache
    @GetMapping("/api/user/{id}")
    public ResponseEntity<User> getUserDetails(@PathVariable Long id) {
        User user = userService.findById(id);
        
        // Thiếu header không cho phép cache
        return ResponseEntity.ok(user);
    }
}

// Mô hình User chứa thông tin nhạy cảm
public class User {
    private Long id;
    private String username;
    private String email;
    private String socialSecurityNumber; // Thông tin nhạy cảm
    private String creditCardNumber;     // Thông tin nhạy cảm
    
    // Getters and setters
}
```

### 2. Lưu trữ dữ liệu nhạy cảm trong Redis Cache (Node.js)

```javascript
// LỖI: Lưu trữ phiên đăng nhập đầy đủ trong Redis (bao gồm cả dữ liệu nhạy cảm)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
      // Tạo session
      const sessionData = {
        userId: user._id,
        username: user.username,
        email: user.email,
        creditCard: user.creditCard,      // Thông tin nhạy cảm
        ssn: user.socialSecurityNumber,   // Thông tin nhạy cảm
        role: user.role
      };
      
      // Lưu toàn bộ sessionData vào Redis cache
      const sessionId = uuidv4();
      await redisClient.set(`session:${sessionId}`, JSON.stringify(sessionData));
      
      // Thiết lập cookie
      res.cookie('sessionId', sessionId);
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Thông tin đăng nhập không chính xác' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Lỗi đăng nhập' });
  }
});
```

## Cách khắc phục

### 1. Thiết lập header HTTP ngăn chặn cache cho dữ liệu nhạy cảm

```java
@RestController
public class UserController {
    
    // Fix: Thêm header ngăn cache cho API trả về thông tin nhạy cảm
    @GetMapping("/api/user/{id}")
    public ResponseEntity<User> getUserDetails(@PathVariable Long id) {
        User user = userService.findById(id);
        
        return ResponseEntity
            .ok()
            .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            .header("Pragma", "no-cache")
            .header("Expires", "0")
            .body(user);
    }
}
```

### 2. Chỉ lưu trữ dữ liệu cần thiết trong cache

```javascript
// Fix: Chỉ lưu trữ các thông tin cần thiết để xác thực phiên
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
      // Tạo session với thông tin tối thiểu
      const sessionData = {
        userId: user._id,
        role: user.role
      };
      
      // Lưu thông tin tối thiểu vào Redis cache
      const sessionId = uuidv4();
      await redisClient.set(`session:${sessionId}`, JSON.stringify(sessionData));
      
      // Đặt thời gian hết hạn cho cache
      await redisClient.expire(`session:${sessionId}`, 3600); // 1 giờ
      
      // Thiết lập cookie
      res.cookie('sessionId', sessionId, { 
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
      });
      
      // Trả về dữ liệu không nhạy cảm
      res.json({ 
        success: true, 
        username: user.username,
        role: user.role
      });
    } else {
      res.status(401).json({ error: 'Thông tin đăng nhập không chính xác' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Lỗi đăng nhập' });
  }
});
```

### 3. Mã hóa dữ liệu nhạy cảm nếu bắt buộc phải lưu cache

```javascript
// Fix: Mã hóa dữ liệu nhạy cảm trong cache nếu cần thiết
const crypto = require('crypto');

// Khóa mã hóa được lưu trữ an toàn (không trong cache)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + encrypted + ':' + authTag.toString('hex');
}

function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = parts[1];
  const authTag = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY), iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Lưu dữ liệu nhạy cảm đã được mã hóa trong cache
const encryptedCreditCard = encrypt(user.creditCard);
await redisClient.set(`user:${user.id}:creditCard`, encryptedCreditCard);
```

## Phòng ngừa

1. **Xác định rõ dữ liệu nhạy cảm**: Xác định loại dữ liệu nào được coi là nhạy cảm (PII, thông tin tài chính, thông tin xác thực)

2. **Ngăn chặn cache cho dữ liệu nhạy cảm**:
   - Sử dụng header HTTP `Cache-Control: no-store, no-cache, must-revalidate`
   - Thiết lập `Pragma: no-cache` và `Expires: 0`

3. **Tối thiểu hóa dữ liệu**:
   - Chỉ lưu trữ các thông tin cần thiết trong cache
   - Loại bỏ hoàn toàn thông tin nhạy cảm khỏi response khi không cần thiết

4. **Mã hóa dữ liệu cache**:
   - Nếu bắt buộc phải cache dữ liệu nhạy cảm, hãy mã hóa trước khi lưu trữ
   - Sử dụng thuật toán mã hóa mạnh (AES-256) và quản lý khóa an toàn

5. **Thiết lập thời gian hết hạn cache**:
   - Cấu hình TTL (Time to Live) ngắn cho cache chứa dữ liệu nhạy cảm
   - Tự động xóa dữ liệu khỏi cache sau khi phiên làm việc kết thúc

6. **Kiểm tra cấu hình cache**:
   - Kiểm tra cấu hình cache của CDN, load balancer, proxy
   - Đảm bảo dữ liệu nhạy cảm không bị cache bởi các thành phần trung gian 