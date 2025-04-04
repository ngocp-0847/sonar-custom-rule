# 6.3.1 Đảm bảo sử dụng bộ sinh số ngẫu nhiên an toàn (CSPRNG)

## Reference checklists.
https://docs.google.com/spreadsheets/d/1b6Xx4iUXT3SousU0vb1FQdfwoB8MDPezxPm3TMEAKD4/edit?gid=1836627612#gid=1836627612&range=C31:D31

> 6.3.1	Đảm bảo rằng mọi giá trị ngẫu nhiên (số ngẫu nhiên, tên file ngẫu nhiên, GUID, chuỗi ngẫu nhiên,…) được tạo ra để không thể đoán được bởi kẻ tấn công phải được sinh ra từ một bộ sinh số ngẫu nhiên an toàn (cryptographically secure random number generator – CSPRNG) do mô-đun mật mã được phê duyệt cung cấp.

## Mô tả

Khi phát triển ứng dụng, việc tạo ra các giá trị ngẫu nhiên (số ngẫu nhiên, tên file ngẫu nhiên, GUID, chuỗi ngẫu nhiên) là rất phổ biến. Tuy nhiên, nếu các giá trị này không thực sự ngẫu nhiên hoặc có thể dự đoán được, kẻ tấn công có thể khai thác để thực hiện các cuộc tấn công.

Bộ sinh số ngẫu nhiên an toàn về mặt mật mã (Cryptographically Secure Pseudo-Random Number Generator - CSPRNG) là một thuật toán tạo ra chuỗi số giả ngẫu nhiên không thể đoán trước được về mặt tính toán, ngay cả khi kẻ tấn công biết được một phần của chuỗi.

## Ví dụ Lỗi

### 1. Sử dụng bộ sinh số ngẫu nhiên không an toàn trong JavaScript

```javascript
// LỖI: Sử dụng Math.random() để tạo ID bảo mật
function generateSessionId() {
  return Math.random().toString(36).substring(2, 15);
}

// LỖI: Sử dụng Math.random() để tạo mật khẩu tạm thời
function generateTemporaryPassword() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let password = '';
  for (let i = 0; i < 10; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}
```

### 2. Sử dụng bộ sinh số ngẫu nhiên không an toàn trong Java

```java
// LỖI: Sử dụng java.util.Random cho token xác thực
public class TokenGenerator {
    public String generateAuthToken() {
        Random random = new Random();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}

// LỖI: Sử dụng Random để tạo tên file tạm thời
public String generateTempFileName() {
    Random random = new Random();
    return "tmp_" + random.nextInt(1000000) + ".txt";
}
```

### 3. Sử dụng bộ sinh số ngẫu nhiên không an toàn trong Python

```python
# LỖI: Sử dụng random.randint() cho mã xác thực
import random

def generate_verification_code():
    return random.randint(100000, 999999)

# LỖI: Sử dụng random.choice() cho khóa bí mật
def generate_api_key():
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(32))
```

### 4. Sử dụng bộ sinh số ngẫu nhiên không an toàn trong PHP

```php
// LỖI: Sử dụng rand() để tạo token CSRF
function generateCsrfToken() {
    return md5(rand() . time());
}

// LỖI: Sử dụng mt_rand() để tạo chuỗi ngẫu nhiên
function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[mt_rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}
```

## Cách Khắc Phục

### 1. JavaScript: Sử dụng Web Crypto API

```javascript
// Đúng: Sử dụng Web Crypto API để tạo ID bảo mật
async function generateSecureSessionId() {
  const array = new Uint8Array(16);
  window.crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Đúng: Sử dụng Web Crypto API để tạo mật khẩu tạm thời
function generateSecureTemporaryPassword(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomArray = new Uint8Array(length);
  window.crypto.getRandomValues(randomArray);
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(randomArray[i] % chars.length);
  }
  return password;
}
```

### 2. Node.js: Sử dụng crypto module

```javascript
const crypto = require('crypto');

// Đúng: Sử dụng crypto.randomBytes() để tạo ID bảo mật
function generateSecureSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// Đúng: Sử dụng crypto.randomBytes() để tạo mật khẩu tạm thời
function generateSecureTemporaryPassword(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomBytes = crypto.randomBytes(length);
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(randomBytes[i] % chars.length);
  }
  return password;
}
```

### 3. Java: Sử dụng SecureRandom

```java
import java.security.SecureRandom;
import java.util.Base64;

public class SecureTokenGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();
    
    // Đúng: Sử dụng SecureRandom cho token xác thực
    public String generateAuthToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    // Đúng: Sử dụng SecureRandom để tạo tên file tạm thời
    public String generateTempFileName() {
        return "tmp_" + secureRandom.nextInt(1000000) + ".txt";
    }
    
    // Đúng: Tạo UUID ngẫu nhiên an toàn
    public String generateSecureUUID() {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        
        // Đặt phiên bản UUID (phiên bản 4, ngẫu nhiên)
        randomBytes[6] &= 0x0f;
        randomBytes[6] |= 0x40;
        randomBytes[8] &= 0x3f;
        randomBytes[8] |= 0x80;
        
        StringBuilder uuid = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            uuid.append(String.format("%02x", randomBytes[i]));
            if (i == 3 || i == 5 || i == 7 || i == 9) {
                uuid.append("-");
            }
        }
        return uuid.toString();
    }
}
```

### 4. Python: Sử dụng secrets module

```python
# Đúng: Sử dụng secrets module cho mã xác thực
import secrets

def generate_secure_verification_code():
    return secrets.randbelow(900000) + 100000

# Đúng: Sử dụng secrets.token_hex() cho khóa API
def generate_secure_api_key():
    return secrets.token_hex(16)  # 32 ký tự hex

# Đúng: Tạo chuỗi ngẫu nhiên an toàn
def generate_secure_random_string(length=10):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(secrets.choice(chars) for _ in range(length))

# Đúng: Tạo mã thông báo URL an toàn
def generate_secure_url_token():
    return secrets.token_urlsafe(16)  # Khoảng 22 ký tự
```

### 5. PHP: Sử dụng random_bytes() hoặc random_int()

```php
// Đúng: Sử dụng random_bytes() để tạo token CSRF
function generateSecureCsrfToken() {
    return bin2hex(random_bytes(32));
}

// Đúng: Sử dụng random_int() để tạo chuỗi ngẫu nhiên
function generateSecureRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[random_int(0, $charactersLength - 1)];
    }
    return $randomString;
}

// Đúng: Tạo UUID v4 an toàn
function generateSecureUuidV4() {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
```

## Phòng Ngừa

### 1. Quy tắc chung

- **Không bao giờ** sử dụng các hàm sinh số ngẫu nhiên không an toàn cho các mục đích bảo mật:
  - JavaScript: `Math.random()`
  - Java: `java.util.Random`
  - Python: `random` module (trừ `random.SystemRandom`)
  - PHP: `rand()`, `mt_rand()`
  - C/C++: `rand()`, `srand()`

- **Luôn sử dụng** các bộ sinh số ngẫu nhiên an toàn về mặt mật mã:
  - JavaScript (Browser): `window.crypto.getRandomValues()`
  - Node.js: `crypto.randomBytes()`
  - Java: `java.security.SecureRandom`
  - Python: `secrets` module
  - PHP: `random_bytes()`, `random_int()`
  - C/C++: `getrandom()` hoặc `/dev/urandom`

### 2. Trường hợp cần sử dụng CSPRNG

Luôn sử dụng CSPRNG cho các trường hợp sau:

- Token xác thực và phiên làm việc
- Mã xác minh một lần (OTP)
- Mật khẩu tạm thời
- Khóa mã hóa và vector khởi tạo (IV)
- Salt cho hashing
- Token CSRF
- Tên file tạm thời (trong trường hợp nhạy cảm)
- UUID/GUID (khi được sử dụng cho mục đích bảo mật)
- Giá trị nonce trong giao thức mật mã
- ID giao dịch

### 3. Kiểm tra và review code

- Thực hiện review code tập trung vào việc sử dụng các hàm sinh số ngẫu nhiên
- Sử dụng công cụ phân tích mã tĩnh để phát hiện việc sử dụng các hàm không an toàn
- Áp dụng các quy tắc và hướng dẫn code để đảm bảo chỉ sử dụng CSPRNG

### 4. Testing

- Kiểm tra phân phối thống kê của các giá trị ngẫu nhiên được tạo ra
- Thực hiện kiểm tra bảo mật (security testing) để phát hiện các vấn đề liên quan đến tính ngẫu nhiên

## Tham khảo

1. [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
2. [NIST SP 800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
3. [MDN Web Docs: Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
4. [Python Documentation: secrets module](https://docs.python.org/3/library/secrets.html) 