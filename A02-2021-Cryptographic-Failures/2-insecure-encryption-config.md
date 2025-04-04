# Lỗi: Cấu Hình Không An Toàn của Initialization Vector, Cipher và Block Modes

## Mô tả
Lỗi này xảy ra khi các thành phần quan trọng của quá trình mã hóa được cấu hình không đúng cách. Initialization Vector (IV), chế độ cipher (block modes) và các cấu hình mã hóa khác nếu không được thiết lập đúng có thể dẫn đến các lỗ hổng bảo mật nghiêm trọng, cho phép kẻ tấn công giải mã dữ liệu mà không cần biết khóa.

## Ví dụ Lỗi

### 1. Sử dụng IV tĩnh hoặc dự đoán được (Java)

```java
public class InsecureEncryption {
    
    // LỖI: Sử dụng IV cố định
    private static final byte[] STATIC_IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    public static String encrypt(String plainText, String key) throws Exception {
        // Khởi tạo cipher với một IV cố định
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        
        // LỖI: Sử dụng IV cố định cho mọi lần mã hóa
        IvParameterSpec ivSpec = new IvParameterSpec(STATIC_IV);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decrypt(String encryptedText, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        
        // LỖI: Sử dụng cùng IV cố định cho giải mã
        IvParameterSpec ivSpec = new IvParameterSpec(STATIC_IV);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(original);
    }
}
```

### 2. Sử dụng chế độ không an toàn ECB (JavaScript/Node.js)

```javascript
const crypto = require('crypto');

// LỖI: Sử dụng chế độ ECB không an toàn
function encryptData(text, key) {
  // LỖI: Chế độ ECB không sử dụng IV và không an toàn
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encrypted, key) {
  const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Sử dụng hàm mã hóa không an toàn
const sensitiveData = 'Credit card: 4111-1111-1111-1111';
const key = crypto.scryptSync('password', 'salt', 32); // 256-bit key

// Mã hóa dữ liệu với ECB mode (không an toàn)
const encryptedData = encryptData(sensitiveData, key);
console.log('Encrypted:', encryptedData);
```

### 3. Không lưu trữ IV cùng với dữ liệu được mã hóa (Python)

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def encrypt_data(data, key):
    # Tạo IV ngẫu nhiên
    iv = os.urandom(16)
    
    # Khởi tạo cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Đảm bảo dữ liệu có độ dài là bội số của kích thước block
    padded_data = data + (16 - len(data) % 16) * chr(16 - len(data) % 16)
    
    # Mã hóa dữ liệu
    encrypted_data = encryptor.update(padded_data.encode()) + encryptor.finalize()
    
    # LỖI: Trả về dữ liệu đã mã hóa mà không lưu IV
    # Điều này làm cho việc giải mã sẽ không thể thực hiện được
    # vì IV sẽ không có sẵn khi giải mã
    return base64.b64encode(encrypted_data).decode()
```

## Cách Khắc Phục

### 1. Sử dụng IV ngẫu nhiên và duy nhất cho mỗi lần mã hóa (Java)

```java
public class SecureEncryption {
    
    public static String encrypt(String plainText, String key) throws Exception {
        // Khởi tạo cipher với AES trong chế độ GCM (tốt hơn CBC)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        
        // Fix: Tạo IV ngẫu nhiên cho mỗi lần mã hóa
        byte[] iv = new byte[12]; // 12 bytes for GCM
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        
        // Kết hợp IV và dữ liệu đã mã hóa để lưu trữ/truyền đi
        byte[] encryptedIvAndData = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedIvAndData, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedIvAndData, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(encryptedIvAndData);
    }
    
    public static String decrypt(String encryptedText, String key) throws Exception {
        byte[] encryptedIvAndData = Base64.getDecoder().decode(encryptedText);
        
        // Tách IV và dữ liệu đã mã hóa
        byte[] iv = new byte[12];
        byte[] encryptedData = new byte[encryptedIvAndData.length - 12];
        
        System.arraycopy(encryptedIvAndData, 0, iv, 0, iv.length);
        System.arraycopy(encryptedIvAndData, iv.length, encryptedData, 0, encryptedData.length);
        
        // Khởi tạo cipher với IV đã được trích xuất
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] original = cipher.doFinal(encryptedData);
        
        return new String(original);
    }
}
```

### 2. Sử dụng chế độ mã hóa an toàn (Node.js)

```javascript
const crypto = require('crypto');

// FIX: Sử dụng GCM thay vì ECB
function encryptData(text, key) {
  // Tạo IV ngẫu nhiên
  const iv = crypto.randomBytes(16);
  
  // Sử dụng chế độ GCM thay vì ECB
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Lấy auth tag từ GCM (quan trọng cho quá trình xác thực)
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Trả về cả IV, authTag và dữ liệu đã mã hóa
  return {
    iv: iv.toString('hex'),
    authTag: authTag,
    encryptedData: encrypted
  };
}

function decryptData(encrypted, key) {
  // Chuyển đổi dữ liệu hex thành Buffer
  const iv = Buffer.from(encrypted.iv, 'hex');
  const authTag = Buffer.from(encrypted.authTag, 'hex');
  
  // Tạo decipher với IV
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  
  // Thiết lập authTag để xác thực
  decipher.setAuthTag(authTag);
  
  // Giải mã dữ liệu
  let decrypted = decipher.update(encrypted.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// Sử dụng hàm mã hóa đã được sửa
const sensitiveData = 'Credit card: 4111-1111-1111-1111';
const key = crypto.scryptSync('password', 'salt', 32); // 256-bit key

// Mã hóa dữ liệu với GCM mode (an toàn)
const encryptedData = encryptData(sensitiveData, key);
console.log('Encrypted:', encryptedData);

// Giải mã dữ liệu
const decryptedData = decryptData(encryptedData, key);
console.log('Decrypted:', decryptedData);
```

### 3. Lưu trữ IV cùng với dữ liệu mã hóa (Python)

```python
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def encrypt_data(data, key):
    # Tạo IV ngẫu nhiên
    iv = os.urandom(16)
    
    # Khởi tạo cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Mã hóa dữ liệu (GCM không cần padding)
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    
    # Lấy tag xác thực
    tag = encryptor.tag
    
    # FIX: Kết hợp IV, tag và dữ liệu mã hóa
    result = {
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(encrypted_data).decode()
    }
    
    return result

def decrypt_data(encrypted_data, key):
    # Lấy các thành phần từ dữ liệu mã hóa
    iv = base64.b64decode(encrypted_data['iv'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # Khởi tạo cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    
    # Giải mã
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_data.decode()
```

## Phòng Ngừa

1. **Sử dụng IV ngẫu nhiên và duy nhất**:
   - Tạo IV ngẫu nhiên mới cho mỗi quá trình mã hóa
   - Không bao giờ sử dụng IV cố định hoặc IV dễ đoán
   - Lưu trữ IV cùng với dữ liệu mã hóa

2. **Sử dụng chế độ mã hóa an toàn**:
   - Ưu tiên các chế độ Authenticated Encryption (AEAD) như GCM
   - Tránh sử dụng chế độ ECB
   - Nếu sử dụng CBC, luôn đảm bảo IV là ngẫu nhiên

3. **Lưu trữ tag xác thực (nếu có)**:
   - Đối với các chế độ như GCM, luôn lưu trữ và sử dụng authentication tag
   - Kiểm tra tag xác thực trong quá trình giải mã

4. **Cập nhật thuật toán mã hóa**:
   - Sử dụng các tiêu chuẩn mã hóa hiện đại (AES-256, ChaCha20)
   - Tránh các thuật toán lỗi thời (DES, 3DES)
   - Theo dõi các khuyến nghị mới từ các tổ chức bảo mật

5. **Quản lý khóa an toàn**:
   - Thực hiện rotation key định kỳ
   - Lưu trữ khóa mã hóa trong hardware security modules (HSM) nếu có thể
   - Không bao giờ hard-code khóa mã hóa trong mã nguồn 