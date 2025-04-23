# Dự Án Kiểm Tra Tính Năng SonarSource

Dự án này được tạo ra để kiểm tra và nghiên cứu các tính năng của SonarSource (SonarQube) trong việc phát hiện các lỗi bảo mật và chất lượng mã nguồn.

## Mục Tiêu

- Kiểm tra khả năng phát hiện lỗi bảo mật của SonarQube với các mẫu mã nguồn khác nhau
- Thử nghiệm cấu hình SonarQube với các ngôn ngữ lập trình khác nhau (TypeScript)
- Hiểu rõ cách SonarQube phân tích và báo cáo các vấn đề bảo mật

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


curl -u sqp_007c72c1b10c1a33672d7e9fc08d8d3776900d55: \
  "http://localhost:9000/api/issues/search?componentKeys=app_test&types=BUG,VULNERABILITY,CODE_SMELL&p=1&ps=500" \
  -o result.json

