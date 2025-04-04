# Hướng Dẫn Cấu Hình Mã Hóa An Toàn
## 6.2.3 Vector Khởi Tạo Mã Hóa, Cấu Hình Mã Hóa, và Chế Độ Khối

> 6.2.3	Encryption initialization vector, cipher configuration, and block modes được cấu hình an toàn
https://docs.google.com/spreadsheets/d/1b6Xx4iUXT3SousU0vb1FQdfwoB8MDPezxPm3TMEAKD4/edit?gid=1836627612#gid=1836627612&range=C25:D25

## Tổng Quan
- CWE-326: Độ Mạnh Mã Hóa Không Đầy Đủ
https://cwe.mitre.org/data/definitions/326.html
- SonarQube: S2076 - AES ECB mode should not be used
http://localhost:9000/coding_rules?owaspTop10-2021=a2&q=encryption+initialization&sonarsourceSecurity=weak-cryptography&types=VULNERABILITY&open=python%3AS4426

Tài liệu này cung cấp hướng dẫn về cấu hình đúng các thành phần mã hóa bao gồm vector khởi tạo (IV), cấu hình mã hóa, và các chế độ khối để đảm bảo tư thế bảo mật vững chắc trong ứng dụng.

## Vector Khởi Tạo (IV)

### IV là gì?
Vector khởi tạo là một giá trị ngẫu nhiên hoặc giả ngẫu nhiên được sử dụng kết hợp với khóa bí mật để mã hóa dữ liệu. IV đảm bảo rằng việc mã hóa lặp lại cùng một văn bản thuần với cùng một khóa sẽ tạo ra các đầu ra văn bản mã hóa khác nhau.

### Yêu Cầu Bảo Mật cho IV:

1. **Tính Duy Nhất**: Phải duy nhất cho mỗi hoạt động mã hóa với cùng một khóa
2. **Tính Ngẫu Nhiên**: Được tạo ra bằng bộ tạo số ngẫu nhiên an toàn về mặt mật mã
3. **Độ Dài Thích Hợp**: Phải phù hợp với kích thước khối của mã hóa được chọn
4. **Không Thể Dự Đoán**: Kẻ tấn công không nên có khả năng dự đoán các IV trong tương lai

### Các Lỗ Hổng Phổ Biến:
- Tái sử dụng IV với cùng một khóa
- Sử dụng IV có thể dự đoán được (bộ đếm, dấu thời gian)
- Sử dụng bộ tạo số ngẫu nhiên yếu
- Mã hóa cứng IV trong mã nguồn

## Chế Độ Khối

### Các Chế Độ Khối Phổ Biến:

| Chế độ | Tên Đầy Đủ | Yêu Cầu IV | Xác Thực | Ghi Chú |
|--------|------------|------------|----------|---------|
| ECB | Electronic Codebook | Không | Không | Không bao giờ sử dụng cho dữ liệu nhạy cảm |
| CBC | Cipher Block Chaining | IV ngẫu nhiên | Không | Dễ bị tấn công bởi padding oracle |
| CTR | Counter | Nonce duy nhất | Không | Yêu cầu xác thực bổ sung |
| GCM | Galois/Counter Mode | IV duy nhất | Có | Được khuyến nghị cho hầu hết các trường hợp |
| CCM | Counter with CBC-MAC | Nonce duy nhất | Có | Phổ biến trong môi trường hạn chế |

### Khuyến Nghị:
- **Ưu tiên các chế độ mã hóa có xác thực** (GCM, CCM) hơn các chế độ không xác thực
- **Không bao giờ sử dụng chế độ ECB** để mã hóa nhiều hơn một khối dữ liệu
- Nếu sử dụng chế độ CBC, hãy thực hiện xác thực padding đúng cách

## Cấu Hình Mã Hóa An Toàn

### Lựa Chọn Khóa:
- Sử dụng kích thước khóa phù hợp (AES-256, RSA-2048+)
- Tạo và lưu trữ khóa mã hóa một cách an toàn
- Thực hiện các quy trình xoay vòng khóa đúng cách

### Cấu Hình Khuyến Nghị:
- AES-256-GCM với IV ngẫu nhiên 12 byte
- ChaCha20-Poly1305 với nonce 12 byte
- RSA với padding OAEP và kích thước khóa phù hợp

### Ví Dụ Triển Khai

#### Ví Dụ Java (AES-GCM)
```java
// Triển khai AES-GCM an toàn
SecureRandom secureRandom = new SecureRandom();
byte[] iv = new byte[12]; // 96 bits cho GCM
secureRandom.nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

byte[] ciphertext = cipher.doFinal(plaintext);
// Lưu trữ cả IV và văn bản mã hóa để giải mã
```

#### Ví Dụ Node.js (AES-GCM)
```javascript
const crypto = require('crypto');

// Tạo một IV ngẫu nhiên
const iv = crypto.randomBytes(12);

// Tạo mã hóa với AES-GCM
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(plaintext, 'utf8', 'base64');
encrypted += cipher.final('base64');

// Lấy thẻ xác thực
const authTag = cipher.getAuthTag();

// Lưu trữ IV, dữ liệu mã hóa, và thẻ xác thực để giải mã
```

## Các Lỗi Thường Gặp Cần Tránh

1. **Cài đặt mặc định không an toàn**: Nhiều thư viện mặc định sử dụng các chế độ không an toàn
2. **Xác thực padding không đúng cách**: Có thể dẫn đến các cuộc tấn công padding oracle
3. **IV tĩnh hoặc có thể dự đoán**: Làm suy yếu bảo mật của mã hóa
4. **Thiếu xác thực**: Cho phép kẻ tấn công thay đổi văn bản mã hóa mà không bị phát hiện
5. **Triển khai chế độ thủ công**: Dễ dẫn đến các lỗi tinh vi trong các hoạt động mật mã phức tạp

## Tóm Tắt Các Thực Hành Tốt Nhất

1. **Sử dụng mã hóa có xác thực**: Ưu tiên AES-GCM, ChaCha20-Poly1305
2. **Tạo IV an toàn về mặt mật mã**: Sử dụng các bộ tạo số ngẫu nhiên an toàn
3. **Không bao giờ tái sử dụng IV với cùng một khóa**
4. **Lưu trữ IV cùng với văn bản mã hóa**: IV không cần phải bí mật
5. **Sử dụng các thư viện mật mã đã được thiết lập**: Tránh tự triển khai các nguyên thủy mật mã
6. **Kiểm tra cấu hình mã hóa**: Sử dụng các công cụ tự động để xác minh bảo mật
7. **Cập nhật thông tin về các lỗ hổng**: Cập nhật triển khai khi phát hiện các điểm yếu

## Tham Khảo
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP ASVS v4.0 Section 6.2: Algorithms](https://owasp.org/www-project-application-security-verification-standard/)
- [Cryptographic Failures in OWASP Top 10 2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
