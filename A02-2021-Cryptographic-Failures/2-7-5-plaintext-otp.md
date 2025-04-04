# Lỗi: Lưu OTP Dưới Dạng Văn Bản Rõ (Plaintext)

## Mô tả

Ref:
- CWE-256: Plaintext Storage of a Password
https://cwe.mitre.org/data/definitions/256.html

One Time Password (OTP) là một mã xác thực sử dụng một lần được gửi tới người dùng qua SMS, email hoặc ứng dụng xác thực. Khi OTP được lưu trữ dưới dạng văn bản rõ (plaintext) trong cơ sở dữ liệu hoặc log, có nguy cơ cao bị đánh cắp và sử dụng trái phép.

## Ví dụ Lỗi

### 1. Lưu OTP dưới dạng plaintext trong cơ sở dữ liệu (Node.js)

```javascript
// Tạo OTP
function generateOTP() {
  const digits = '0123456789';
  let OTP = '';
  for (let i = 0; i < 6; i++) {
    OTP += digits[Math.floor(Math.random() * 10)];
  }
  return OTP;
}

// LỖI: Lưu OTP dưới dạng plaintext trong DB
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(404).json({ error: 'Người dùng không tồn tại' });
  }
  
  // Tạo OTP
  const otp = generateOTP();
  
  // Lưu OTP dưới dạng plaintext vào DB
  await OTP.create({
    userId: user._id,
    otp: otp, // LỖI: OTP lưu dưới dạng plaintext
    expires: new Date(Date.now() + 10 * 60 * 1000) // Hết hạn sau 10 phút
  });
  
  // Gửi OTP qua email
  await sendOTPEmail(email, otp);
  
  return res.json({ message: 'OTP đã được gửi' });
});

// LỖI: Xác thực OTP bằng cách so sánh plaintext
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(404).json({ error: 'Người dùng không tồn tại' });
  }
  
  // Tìm OTP trong DB
  const otpRecord = await OTP.findOne({
    userId: user._id,
    otp: otp, // LỖI: So sánh OTP dưới dạng plaintext
    expires: { $gt: new Date() }
  });
  
  if (!otpRecord) {
    return res.status(400).json({ error: 'OTP không hợp lệ hoặc đã hết hạn' });
  }
  
  // Xóa OTP sau khi xác thực
  await OTP.deleteOne({ _id: otpRecord._id });
  
  // Xác thực thành công
  return res.json({ message: 'Xác thực thành công' });
});
```

### 2. In OTP ra log (Java)

```java
@Service
public class OTPService {

    private final Logger logger = LoggerFactory.getLogger(OTPService.class);
    
    // Tạo OTP
    public String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
    
    // LỖI: Ghi OTP vào log
    public void sendOTP(String email, String otp) {
        // Ghi OTP vào log (LỖI)
        logger.info("OTP sent to user {}: {}", email, otp);
        
        // Gửi OTP qua email
        emailService.sendEmail(email, "Your OTP", "Your OTP is: " + otp);
    }
}
```

## Cách Khắc Phục

### 1. Lưu OTP đã được mã hóa hoặc hash

```javascript
const crypto = require('crypto');

// Hàm tạo OTP
function generateOTP() {
  const digits = '0123456789';
  let OTP = '';
  for (let i = 0; i < 6; i++) {
    OTP += digits[Math.floor(Math.random() * 10)];
  }
  return OTP;
}

// Hàm hash OTP với salt
function hashOTP(otp, userId) {
  // Sử dụng userId làm salt
  const salt = userId.toString();
  return crypto.createHmac('sha256', salt).update(otp).digest('hex');
}

// SỬALỖI: Lưu hash của OTP thay vì plaintext
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(404).json({ error: 'Người dùng không tồn tại' });
  }
  
  // Tạo OTP
  const otp = generateOTP();
  
  // Hash OTP trước khi lưu vào DB
  const hashedOTP = hashOTP(otp, user._id);
  
  // Lưu hash của OTP vào DB
  await OTP.create({
    userId: user._id,
    otpHash: hashedOTP, // FIX: Lưu hash thay vì plaintext
    expires: new Date(Date.now() + 10 * 60 * 1000)
  });
  
  // Gửi OTP qua email (OTP gốc, không phải hash)
  await sendOTPEmail(email, otp);
  
  return res.json({ message: 'OTP đã được gửi' });
});

// SỬALỖI: Xác thực OTP bằng cách so sánh hash
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  
  if (!user) {
    return res.status(404).json({ error: 'Người dùng không tồn tại' });
  }
  
  // Hash OTP đầu vào để so sánh
  const hashedInputOTP = hashOTP(otp, user._id);
  
  // Tìm OTP trong DB bằng hash
  const otpRecord = await OTP.findOne({
    userId: user._id,
    otpHash: hashedInputOTP, // FIX: So sánh hash thay vì plaintext
    expires: { $gt: new Date() }
  });
  
  if (!otpRecord) {
    return res.status(400).json({ error: 'OTP không hợp lệ hoặc đã hết hạn' });
  }
  
  // Xóa OTP sau khi xác thực
  await OTP.deleteOne({ _id: otpRecord._id });
  
  // Xác thực thành công
  return res.json({ message: 'Xác thực thành công' });
});
```

### 2. Không in OTP ra log

```java
@Service
public class OTPService {

    private final Logger logger = LoggerFactory.getLogger(OTPService.class);
    
    // Tạo OTP
    public String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
    
    // SỬALỖI: Không ghi OTP vào log
    public void sendOTP(String email, String otp) {
        // FIX: Không ghi OTP vào log
        logger.info("OTP sent to user: {}", email);
        
        // Gửi OTP qua email
        emailService.sendEmail(email, "Your OTP", "Your OTP is: " + otp);
    }
}
```

## Phòng Ngừa

1. **Mã hóa hoặc hash OTP**:
   - Sử dụng thuật toán hash mạnh (SHA-256) kết hợp với salt
   - Không bao giờ lưu OTP dưới dạng plaintext

2. **Quản lý log an toàn**:
   - Không ghi OTP vào file log hoặc console
   - Lọc thông tin nhạy cảm từ log

3. **Thời gian sống (TTL) ngắn cho OTP**:
   - Thiết lập thời gian hết hạn ngắn (5-10 phút)
   - Xóa OTP ngay sau khi xác thực thành công

4. **Giới hạn số lần thử**:
   - Khóa tài khoản sau một số lần nhập OTP sai nhất định
   - Triển khai cơ chế chống brute-force

5. **Sử dụng token thay vì OTP nếu có thể**:
   - Token JWT có thể an toàn hơn trong một số trường hợp
   - Token có thể được ký bằng khóa bí mật, không cần lưu trong DB 