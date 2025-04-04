# Lỗi: Không Phân Loại và Lưu Trữ Thông Tin Cá Nhân Nhạy Cảm Đúng Cách

## Reference checklists.
> 8.3.8 Verify that sensitive personal information is subject to data retention
classification, such that old or out of date data is deleted automatically, on a
schedule, or as the situation requires. ✓ ✓ 285

- CWE-285: Improper Authorization
https://cwe.mitre.org/data/definitions/285.html

## Mô tả
Lỗi này xảy ra khi hệ thống không có cơ chế phân loại dữ liệu và chính sách lưu trữ thông tin cá nhân nhạy cảm phù hợp. Việc lưu trữ dữ liệu nhạy cảm vô thời hạn tạo ra rủi ro bảo mật lớn, vi phạm các quy định về bảo vệ dữ liệu (như GDPR, CCPA) và làm tăng mức độ nghiêm trọng khi xảy ra sự cố rò rỉ dữ liệu. Thông tin cá nhân nhạy cảm (PII - Personally Identifiable Information) cần được phân loại, lưu trữ có thời hạn và xóa bỏ khi hết hạn sử dụng.

## Ví dụ Lỗi

### 1. Lưu trữ dữ liệu người dùng vô thời hạn (SQL)

```sql
-- LỖI: Bảng dữ liệu người dùng không có cơ chế quản lý thời hạn lưu trữ
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    social_security_number VARCHAR(20) NOT NULL,
    credit_card_number VARCHAR(20),
    credit_card_cvv VARCHAR(5),
    home_address TEXT,
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    -- LỖI: Không có trường để đánh dấu khi nào dữ liệu hết hạn hoặc cần xóa
);

-- LỖI: Lưu trữ lịch sử giao dịch và thông tin thanh toán vô thời hạn
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    transaction_type VARCHAR(50) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    credit_card_number VARCHAR(20) NOT NULL,
    billing_address TEXT NOT NULL,
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
    -- LỖI: Không có cơ chế tự động xóa hoặc ẩn danh hóa dữ liệu cũ
);
```

### 2. Xử lý dữ liệu không tuân thủ chính sách lưu trữ (Java)

```java
// LỖI: Không có cơ chế phân loại dữ liệu và quản lý thời hạn lưu trữ
@Entity
@Table(name = "customer_data")
public class CustomerData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String fullName;
    private String email;
    private String phoneNumber;
    private String address;
    private Date dateOfBirth;
    
    // LỖI: Lưu trữ thông tin nhạy cảm mà không phân loại
    private String socialSecurityNumber;
    private String passportNumber;
    private String medicalRecordNumber;
    
    @Column(name = "created_at")
    private Date createdAt;
    
    // LỖI: Không có trường thời hạn lưu trữ hoặc ngày hết hạn
    // LỖI: Không có cơ chế tự động xóa dữ liệu sau khi hết hạn
    
    // Getters and setters...
}

// LỖI: Service không xử lý vấn đề hết hạn dữ liệu
@Service
public class CustomerDataService {
    @Autowired
    private CustomerDataRepository repository;
    
    public CustomerData saveCustomerData(CustomerData data) {
        data.setCreatedAt(new Date());
        // LỖI: Lưu trữ tất cả dữ liệu mà không phân loại độ nhạy cảm
        // LỖI: Không thiết lập thời hạn lưu trữ dựa trên loại dữ liệu
        return repository.save(data);
    }
    
    // LỖI: Không có phương thức định kỳ xóa dữ liệu hết hạn
    // LỖI: Không có cơ chế ẩn danh hóa dữ liệu khi không còn cần thiết
}
```

### 3. Lưu trữ dữ liệu log nhạy cảm vô thời hạn (JavaScript/Node.js)

```javascript
// LỖI: Lưu trữ thông tin log có chứa dữ liệu nhạy cảm mà không có chính sách xóa
const winston = require('winston');
const fs = require('fs');

// LỖI: Cấu hình ghi log không có cơ chế xóa log cũ
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    // LỖI: Lưu trữ log vào file mà không có cơ chế xoay vòng hoặc xóa log cũ
    new winston.transports.File({ filename: 'user-activity.log' })
  ]
});

// LỖI: Ghi log chứa thông tin nhạy cảm
function logUserLogin(user) {
  // LỖI: Ghi log thông tin nhạy cảm mà không ẩn danh hóa hay xóa theo thời gian
  logger.info({
    message: 'User logged in',
    userId: user.id,
    email: user.email,
    ipAddress: user.ipAddress,
    // LỖI: Thậm chí còn ghi log thông tin cực kỳ nhạy cảm
    socialSecurityNumber: user.ssn,
    sessionToken: user.sessionToken
  });
}

// LỖI: Không có cơ chế xóa log cũ
// LỖI: Không có phân loại mức độ nhạy cảm trong dữ liệu log
```

## Cách Khắc Phục

### 1. Thiết kế cơ sở dữ liệu với chính sách lưu trữ (SQL)

```sql
-- FIX: Thiết kế bảng với các trường hỗ trợ chính sách lưu trữ dữ liệu
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    
    -- FIX: Phân loại dữ liệu nhạy cảm
    -- Dữ liệu thông thường (lưu trữ lâu dài)
    full_name VARCHAR(100) NOT NULL,
    
    -- Dữ liệu nhạy cảm (có thể lưu trữ với thời hạn dài hơn)
    date_of_birth DATE,
    phone_number VARCHAR(20),
    
    -- Dữ liệu rất nhạy cảm (thời hạn lưu trữ ngắn)
    home_address TEXT,
    
    -- FIX: Các trường quản lý vòng đời dữ liệu
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    retention_period_days INT DEFAULT 730, -- 2 năm mặc định
    scheduled_deletion_date TIMESTAMP GENERATED ALWAYS AS (DATE_ADD(last_activity_date, INTERVAL retention_period_days DAY)) STORED,
    
    -- FIX: Trạng thái người dùng để hỗ trợ chính sách xóa dữ liệu
    is_deleted BOOLEAN DEFAULT FALSE,
    deletion_date TIMESTAMP NULL
);

-- FIX: Bảng riêng cho dữ liệu cực kỳ nhạy cảm với thời hạn lưu trữ ngắn
CREATE TABLE sensitive_user_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    
    -- Dữ liệu cực kỳ nhạy cảm được mã hóa
    social_security_number_encrypted VARBINARY(255),
    
    -- FIX: Quản lý vòng đời dữ liệu
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    retention_days INT DEFAULT 90, -- 3 tháng mặc định
    expires_at TIMESTAMP GENERATED ALWAYS AS (DATE_ADD(created_at, INTERVAL retention_days DAY)) STORED,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- FIX: Bảng giao dịch với chính sách lưu trữ rõ ràng
CREATE TABLE transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    transaction_type VARCHAR(50) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    
    -- Chỉ lưu 4 số cuối thẻ tín dụng thay vì toàn bộ số
    last_four_digits VARCHAR(4) NOT NULL,
    
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- FIX: Thời hạn lưu trữ theo quy định tài chính (7 năm)
    retention_days INT DEFAULT 2555, -- 7 năm
    scheduled_deletion_date TIMESTAMP GENERATED ALWAYS AS (DATE_ADD(transaction_date, INTERVAL retention_days DAY)) STORED,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- FIX: Trigger tự động ẩn danh hóa dữ liệu khi hết hạn
DELIMITER //
CREATE EVENT auto_anonymize_expired_sensitive_data
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    -- Xóa dữ liệu nhạy cảm đã hết hạn
    DELETE FROM sensitive_user_data WHERE expires_at <= NOW();
    
    -- Ẩn danh hóa thông tin giao dịch hết hạn
    UPDATE transactions 
    SET last_four_digits = '****'
    WHERE scheduled_deletion_date <= NOW();
END //
DELIMITER ;
```

### 2. Xử lý dữ liệu tuân thủ chính sách lưu trữ (Java)

```java
// FIX: Phân loại dữ liệu và quản lý thời hạn lưu trữ
// Sử dụng annotation để đánh dấu các trường dữ liệu nhạy cảm và loại lưu trữ
public @interface DataRetention {
    RetentionClass classification() default RetentionClass.NORMAL;
    int retentionDays() default 730; // 2 năm mặc định
}

public enum RetentionClass {
    NORMAL,        // Dữ liệu thông thường (2 năm)
    SENSITIVE,     // Dữ liệu nhạy cảm (1 năm)
    HIGHLY_SENSITIVE, // Dữ liệu rất nhạy cảm (90 ngày)
    FINANCIAL      // Dữ liệu tài chính (7 năm - quy định pháp lý)
}

@Entity
@Table(name = "customer_data")
public class CustomerData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Dữ liệu thường
    @DataRetention(classification = RetentionClass.NORMAL)
    private String fullName;
    
    @DataRetention(classification = RetentionClass.NORMAL)
    private String email;
    
    // Dữ liệu nhạy cảm
    @DataRetention(classification = RetentionClass.SENSITIVE, retentionDays = 365)
    private String phoneNumber;
    
    @DataRetention(classification = RetentionClass.SENSITIVE, retentionDays = 365)
    @Convert(converter = EncryptedStringConverter.class) // Mã hóa
    private String address;
    
    // Dữ liệu rất nhạy cảm
    @DataRetention(classification = RetentionClass.HIGHLY_SENSITIVE, retentionDays = 90)
    @Convert(converter = EncryptedStringConverter.class) // Mã hóa
    private String socialSecurityNumber;
    
    @DataRetention(classification = RetentionClass.HIGHLY_SENSITIVE, retentionDays = 90)
    @Convert(converter = EncryptedStringConverter.class) // Mã hóa
    private String passportNumber;
    
    @Column(name = "created_at")
    private Date createdAt;
    
    // FIX: Thêm trường để quản lý thời hạn lưu trữ
    @Column(name = "retention_period_days")
    private Integer retentionPeriodDays;
    
    @Column(name = "scheduled_deletion_date")
    private Date scheduledDeletionDate;
    
    // FIX: Getters và setters
}

// FIX: Service có cơ chế xóa tự động
@Service
public class CustomerDataService {
    @Autowired
    private CustomerDataRepository repository;
    
    // FIX: Lưu dữ liệu với phân loại thời hạn lưu trữ phù hợp
    public CustomerData saveCustomerData(CustomerData data) {
        data.setCreatedAt(new Date());
        
        // Xác định thời hạn lưu trữ dựa trên dữ liệu nhạy cảm nhất
        int retentionDays = determineRetentionPeriod(data);
        data.setRetentionPeriodDays(retentionDays);
        
        // Tính toán ngày xóa
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(data.getCreatedAt());
        calendar.add(Calendar.DAY_OF_MONTH, retentionDays);
        data.setScheduledDeletionDate(calendar.getTime());
        
        return repository.save(data);
    }
    
    // FIX: Xác định thời hạn lưu trữ dựa trên dữ liệu nhạy cảm nhất
    private int determineRetentionPeriod(CustomerData data) {
        // Sử dụng reflection để kiểm tra các annotation
        int shortestRetention = Integer.MAX_VALUE;
        
        for (Field field : CustomerData.class.getDeclaredFields()) {
            DataRetention retention = field.getAnnotation(DataRetention.class);
            if (retention != null) {
                field.setAccessible(true);
                try {
                    Object value = field.get(data);
                    if (value != null && !value.toString().isEmpty()) {
                        if (retention.retentionDays() < shortestRetention) {
                            shortestRetention = retention.retentionDays();
                        }
                    }
                } catch (IllegalAccessException e) {
                    // Xử lý ngoại lệ
                }
            }
        }
        
        return shortestRetention == Integer.MAX_VALUE ? 730 : shortestRetention;
    }
    
    // FIX: Job tự động xóa dữ liệu hết hạn
    @Scheduled(cron = "0 0 1 * * ?") // Chạy vào 1 giờ sáng mỗi ngày
    public void deleteExpiredData() {
        Date today = new Date();
        List<CustomerData> expiredData = repository.findByScheduledDeletionDateBefore(today);
        
        for (CustomerData data : expiredData) {
            // Lưu trữ data tối thiểu cần thiết cho kiểm toán (nếu cần)
            logDataDeletion(data.getId());
            
            // Xóa hoặc ẩn danh hóa dữ liệu
            anonymizeOrDeleteData(data);
        }
    }
    
    // FIX: Ẩn danh hóa dữ liệu thay vì xóa hoàn toàn (nếu cần lưu trữ cho mục đích thống kê)
    private void anonymizeOrDeleteData(CustomerData data) {
        // Xóa dữ liệu nhạy cảm
        data.setSocialSecurityNumber(null);
        data.setPassportNumber(null);
        
        // Ẩn danh hóa dữ liệu cơ bản
        data.setFullName("[DELETED]");
        data.setEmail("[DELETED]");
        data.setPhoneNumber(null);
        data.setAddress(null);
        
        repository.save(data);
    }
}
```

### 3. Quản lý log an toàn (JavaScript/Node.js)

```javascript
// FIX: Sử dụng cơ chế log an toàn với phân loại dữ liệu và xoay vòng log
const winston = require('winston');
require('winston-daily-rotate-file');
const { createLogger, format, transports } = winston;
const { combine, timestamp, printf, splat, json } = format;

// FIX: Lớp lọc thông tin nhạy cảm khỏi log
const sensitiveDataFilter = format((info) => {
  if (info.user) {
    // Tạo bản sao để không thay đổi dữ liệu gốc
    info = { ...info };
    
    // Loại bỏ dữ liệu nhạy cảm
    if (info.user.ssn) info.user.ssn = '[REDACTED]';
    if (info.user.sessionToken) info.user.sessionToken = '[REDACTED]';
    
    // Che giấu một phần địa chỉ email
    if (info.user.email) {
      const [name, domain] = info.user.email.split('@');
      if (name && domain) {
        info.user.email = `${name.substring(0, 2)}***@${domain}`;
      }
    }
  }
  
  return info;
});

// FIX: Cấu hình logger an toàn với cơ chế xoay vòng log theo chính sách lưu trữ
const logger = createLogger({
  level: 'info',
  format: combine(
    timestamp(),
    sensitiveDataFilter(),
    json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    // FIX: Sử dụng daily rotate file để tự động xoay vòng và xóa log cũ
    new transports.DailyRotateFile({
      filename: 'logs/user-activity-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d', // Giữ log trong 14 ngày
      auditFile: 'logs/audit.json',
      zippedArchive: true
    }),
    // FIX: Lưu log nhạy cảm vào file riêng với thời gian lưu trữ ngắn hơn
    new transports.DailyRotateFile({
      filename: 'logs/sensitive-data-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '10m',
      maxFiles: '3d', // Chỉ giữ log nhạy cảm trong 3 ngày
      level: 'warn',
      zippedArchive: true
    })
  ]
});

// FIX: Phân loại log theo mức độ nhạy cảm
function logUserLogin(user) {
  // FIX: Chỉ log thông tin cần thiết, không log dữ liệu nhạy cảm
  logger.info({
    message: 'User logged in',
    userId: user.id,
    user: {
      email: user.email,
      ipAddress: user.ipAddress
      // Không log thông tin nhạy cảm
    }
  });
}

// FIX: Tự động xóa log cũ theo lịch trình
const fs = require('fs').promises;
const path = require('path');
const { CronJob } = require('cron');

// Chạy hàng ngày vào lúc 2 giờ sáng
new CronJob('0 2 * * *', async function() {
  try {
    const sensitiveLogDir = path.join(__dirname, 'logs');
    const files = await fs.readdir(sensitiveLogDir);
    
    const now = new Date();
    for (const file of files) {
      if (file.startsWith('sensitive-data-')) {
        const filePath = path.join(sensitiveLogDir, file);
        const stats = await fs.stat(filePath);
        
        // Tính số ngày kể từ khi file được tạo
        const fileDate = new Date(stats.birthtime);
        const diffDays = Math.floor((now - fileDate) / (1000 * 60 * 60 * 24));
        
        // Xóa các file log nhạy cảm cũ hơn 3 ngày
        if (diffDays > 3) {
          await fs.unlink(filePath);
          console.log(`Deleted old sensitive log: ${file}`);
        }
      }
    }
  } catch (error) {
    console.error('Error cleaning up old logs:', error);
  }
}, null, true);
```

## Phòng Ngừa

1. **Thiết lập chính sách phân loại dữ liệu**:
   - Phân loại dữ liệu theo mức độ nhạy cảm (thông thường, nhạy cảm, rất nhạy cảm)
   - Xác định thời hạn lưu trữ tối đa cho mỗi loại dữ liệu
   - Tuân thủ các quy định pháp lý về lưu trữ dữ liệu (GDPR, CCPA, HIPAA, v.v.)

2. **Triển khai cơ chế tự động xóa dữ liệu**:
   - Thiết lập trường thời hạn lưu trữ và ngày xóa dự kiến
   - Tạo tác vụ theo lịch trình để xóa hoặc ẩn danh hóa dữ liệu hết hạn
   - Cung cấp cơ chế cho người dùng yêu cầu xóa dữ liệu của họ

3. **Mã hóa dữ liệu nhạy cảm**:
   - Mã hóa dữ liệu nhạy cảm khi lưu trữ
   - Thiết lập cơ chế quản lý khóa cho phép xóa dữ liệu mạnh mẽ hơn (xóa khóa)
   - Phân tách lưu trữ dữ liệu nhạy cảm vào các bảng/kho lưu trữ riêng

4. **Quản lý log hiệu quả**:
   - Hạn chế lưu trữ thông tin nhạy cảm trong log
   - Thiết lập chính sách xoay vòng log và xóa log cũ
   - Phân tách log theo mức độ nhạy cảm của dữ liệu

5. **Kiểm toán tuân thủ**:
   - Kiểm tra định kỳ việc tuân thủ chính sách lưu trữ dữ liệu
   - Ghi nhật ký các hoạt động xóa dữ liệu để kiểm toán
   - Tạo báo cáo về vòng đời dữ liệu và việc tuân thủ chính sách

## Tác động của lỗi
Lưu trữ thông tin cá nhân nhạy cảm không đúng cách có thể dẫn đến:
1. Vi phạm quy định bảo vệ dữ liệu như GDPR, CCPA và các hình phạt tài chính
2. Gia tăng tác động của các vụ rò rỉ dữ liệu
3. Mất lòng tin của khách hàng và thiệt hại về uy tín
4. Tăng chi phí lưu trữ và quản lý dữ liệu không cần thiết

## Tài liệu tham khảo
1. [GDPR Article 5 & 17 - Principles & Right to Erasure](https://gdpr-info.eu/art-5-gdpr/)
2. [NIST SP 800-122: Guide to Protecting PII](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf)
3. [OWASP Data Retention Policy Template](https://owasp.org/www-community/Data_Retention_Policy)
4. [ISO/IEC 27701:2019 - Privacy Information Management](https://www.iso.org/standard/71670.html) 