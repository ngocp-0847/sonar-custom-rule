# 9.1.3 Đảm bảo sử dụng phiên bản TLS mới nhất

## Rule sonarsource.

- csharpsquid:S4830
- javascript:S4830
- java:S4830
- php:S4830
- python:S4830
- kotlin:S4830    

- typescript:S5527 (Server hostnames should be verified during SSL/TLS connections)


## Reference checklist
https://docs.google.com/spreadsheets/d/1b6Xx4iUXT3SousU0vb1FQdfwoB8MDPezxPm3TMEAKD4/edit?gid=1836627612#gid=1836627612&range=C44:D44

> 9.1.3 Đảm bảo rằng hệ thống chỉ cho phép các phiên bản TLS mới nhất, cụ thể là TLS 1.2 và TLS 1.3, được kích hoạt để bảo vệ giao tiếp

## Mô tả

Transport Layer Security (TLS) là giao thức mã hóa được sử dụng rộng rãi để bảo vệ dữ liệu khi truyền tải qua mạng. Các phiên bản cũ của TLS (TLS 1.0, TLS 1.1) và tiền thân của nó là SSL (SSL 2.0, SSL 3.0) đã được xác định có nhiều lỗ hổng bảo mật nghiêm trọng và không còn an toàn để sử dụng.

Việc sử dụng các phiên bản TLS cũ có thể khiến hệ thống dễ bị tấn công bởi:
- BEAST (Browser Exploit Against SSL/TLS)
- POODLE (Padding Oracle On Downgraded Legacy Encryption)
- FREAK (Factoring RSA Export Keys)
- Tấn công hạ cấp giao thức (Protocol Downgrade Attacks)
- Lỗ hổng rò rỉ thông tin (Information Leakage)

## Ví dụ Lỗi

### 1. Cấu hình máy chủ web Nginx cho phép TLS phiên bản cũ

```nginx
# LỖI: Cấu hình nginx.conf cho phép TLS 1.0 và TLS 1.1
server {
    listen 443 ssl;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # LỖI: Cho phép tất cả các phiên bản TLS, bao gồm cả phiên bản cũ
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
    
    # LỖI: Bộ mã hóa yếu
    ssl_ciphers ALL:!aNULL:!eNULL:!LOW:!MEDIUM:HIGH:!EXP;
    ssl_prefer_server_ciphers on;
    
    # Cấu hình khác...
}
```

### 2. Cấu hình máy chủ web Apache cho phép TLS phiên bản cũ

```apache
# LỖI: Cấu hình Apache cho phép TLS 1.0 và TLS 1.1
<VirtualHost *:443>
    ServerName example.com
    
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/example.com.crt
    SSLCertificateKeyFile /etc/apache2/ssl/example.com.key
    
    # LỖI: Cho phép tất cả các phiên bản TLS, bao gồm cả phiên bản cũ
    SSLProtocol all
    
    # LỖI: Bộ mã hóa không an toàn
    SSLCipherSuite ALL:!aNULL:!eNULL:!LOW:!MEDIUM:HIGH:!EXP
    SSLHonorCipherOrder on
    
    # Cấu hình khác...
</VirtualHost>
```

### 3. Cấu hình Java sử dụng phiên bản TLS cũ

```java
// LỖI: Sử dụng TLS 1.0 trong code Java
public void configureSSLContext() {
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1");
        sslContext.init(null, null, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

### 4. Cấu hình Node.js sử dụng phiên bản TLS cũ

```javascript
// LỖI: Sử dụng TLS 1.0 trong Node.js
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem'),
  secureProtocol: 'TLSv1_method', // LỖI: Chỉ sử dụng TLS 1.0
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Hello World\n');
}).listen(8000);
```

## Cách Khắc Phục

### 1. Cấu hình Nginx đúng

```nginx
# ĐÚNG: Cấu hình nginx.conf chỉ cho phép TLS 1.2 và TLS 1.3
server {
    listen 443 ssl;
    server_name example.com;
    
    ssl_certificate /etc/nginx/ssl/example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.key;
    
    # ĐÚNG: Chỉ cho phép TLS 1.2 và TLS 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # ĐÚNG: Chỉ sử dụng bộ mã hóa mạnh
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    
    # Thêm bảo mật với HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # Cấu hình khác...
}
```

### 2. Cấu hình Apache đúng

```apache
# ĐÚNG: Cấu hình Apache chỉ cho phép TLS 1.2 và TLS 1.3
<VirtualHost *:443>
    ServerName example.com
    
    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/example.com.crt
    SSLCertificateKeyFile /etc/apache2/ssl/example.com.key
    
    # ĐÚNG: Chỉ cho phép TLS 1.2 và TLS 1.3
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    
    # ĐÚNG: Chỉ sử dụng bộ mã hóa mạnh
    SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
    SSLHonorCipherOrder on
    
    # Thêm bảo mật với HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    
    # Cấu hình khác...
</VirtualHost>
```

### 3. Cấu hình Java đúng

```java
// ĐÚNG: Sử dụng TLS 1.2 hoặc cao hơn trong code Java
public void configureSSLContext() {
    try {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        
        // Hoặc thiết lập toàn cục
        System.setProperty("https.protocols", "TLSv1.2,TLSv1.3");
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

### 4. Cấu hình Node.js đúng

```javascript
// ĐÚNG: Sử dụng TLS 1.2 hoặc cao hơn trong Node.js
const https = require('https');
const fs = require('fs');
const tls = require('tls');

const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem'),
  minVersion: tls.TLS1_2_VERSION, // ĐÚNG: TLS 1.2 là phiên bản tối thiểu
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Hello World\n');
}).listen(8000);
```

## Phòng Ngừa

### 1. Vô hiệu hóa SSL/TLS cũ trên tất cả các máy chủ

- Vô hiệu hóa SSL 2.0, SSL 3.0, TLS 1.0 và TLS 1.1 trên tất cả máy chủ
- Chỉ cho phép TLS 1.2 và TLS 1.3
- Cập nhật định kỳ cấu hình để đảm bảo tuân thủ các khuyến nghị mới nhất

### 2. Sử dụng bộ mã hóa (cipher suites) mạnh

- Chỉ cho phép các bộ mã hóa mạnh như ECDHE với AES-GCM
- Vô hiệu hóa các bộ mã hóa yếu và dễ bị tấn công
- Sử dụng các công cụ như Mozilla SSL Configuration Generator để tạo cấu hình an toàn

### 3. Kiểm tra cấu hình TLS thường xuyên

- Sử dụng các công cụ như SSL Labs Server Test để kiểm tra cấu hình
- Thực hiện quét bảo mật định kỳ để phát hiện cấu hình TLS không an toàn
- Áp dụng các bản vá bảo mật cho các thành phần liên quan đến TLS

### 4. Giám sát và ghi nhật ký

- Giám sát các cố gắng kết nối sử dụng phiên bản TLS cũ
- Thiết lập cảnh báo khi phát hiện các kết nối không an toàn
- Ghi lại thông tin về phiên bản TLS được sử dụng trong các kết nối

### 5. Chiến lược triển khai

- Lên kế hoạch triển khai cẩn thận để tránh ảnh hưởng đến người dùng
- Thông báo cho người dùng về yêu cầu nâng cấp trình duyệt hoặc ứng dụng
- Xem xét giữ lại TLS 1.1 tạm thời với lộ trình rõ ràng để loại bỏ

## Kiểm tra cấu hình TLS

### Công cụ kiểm tra online

1. **SSL Labs Server Test**: https://www.ssllabs.com/ssltest/
2. **ImmuniWeb SSL Security Test**: https://www.immuniweb.com/ssl/
3. **Observatory by Mozilla**: https://observatory.mozilla.org/

### Công cụ kiểm tra dòng lệnh

1. **OpenSSL**:
```bash
openssl s_client -connect example.com:443 -tls1_2
```

2. **Nmap**:
```bash
nmap --script ssl-enum-ciphers -p 443 example.com
```

3. **testssl.sh**:
```bash
./testssl.sh --protocols example.com
```

## Tham khảo

1. [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
2. [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
3. [PCI DSS v4.0 Requirements for TLS](https://www.pcisecuritystandards.org/documents/PCI_DSS_v4-0.pdf)
4. [NIST Guidelines for TLS Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
5. [RFC 8996 - Deprecating TLS 1.0 and TLS 1.1](https://datatracker.ietf.org/doc/html/rfc8996) 