# Dự Án Kiểm Tra Tính Năng SonarSource

Dự án này được tạo ra để kiểm tra và nghiên cứu các tính năng của SonarSource (SonarQube) trong việc phát hiện các lỗi bảo mật và chất lượng mã nguồn.

## Mục Tiêu

- Kiểm tra khả năng phát hiện lỗi bảo mật của SonarQube với các mẫu mã nguồn khác nhau
- Thử nghiệm cấu hình SonarQube với các ngôn ngữ lập trình khác nhau (TypeScript)
- Hiểu rõ cách SonarQube phân tích và báo cáo các vấn đề bảo mật

## Cấu Trúc Dự Án

- `typescript-super-error/`: Mẫu mã TypeScript để kiểm tra
- `errors/`: Các mẫu mã và tài liệu về lỗi bảo mật phổ biến
  - `pbkdf2.md`: Mẫu về thuật toán mã hóa mật khẩu
  - `slow-hash-algorithm.md`: Ví dụ về thuật toán băm chậm
  - `log-protection.md`: Bảo vệ thông tin nhạy cảm trong log
  - `broken.md`: Các mẫu mã bị lỗi

## Hướng Dẫn Sử Dụng

### Chạy SonarQube bằng Docker

```bash
docker-compose up -d sonarqube
```

Sau khi khởi động, truy cập SonarQube tại địa chỉ: http://localhost:9000  
(Thông tin đăng nhập mặc định: admin/admin)

### Chạy phân tích mã nguồn

```bash
./sonar.sh analyze
```

Hoặc sử dụng Docker Compose để chạy trình quét:

```bash
docker-compose up sonar-scanner
```

## Cấu Hình

- SonarQube được cấu hình trong file `docker-compose.yml`
- Cấu hình quét mã nguồn trong file `sonar.sh`

## Kết Quả

Sau khi phân tích hoàn tất, bạn có thể xem kết quả và các vấn đề phát hiện được trong giao diện web của SonarQube.

