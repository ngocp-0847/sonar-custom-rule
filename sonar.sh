#!/bin/bash

# Sử dụng Docker
# docker run --rm -e SONAR_HOST_URL="http://127.0.0.1:9000" \
#   -e SONAR_SCANNER_OPTS="-Dsonar.token=your_sonar_token" \
#   -v "$(pwd):/usr/src" sonarsource/sonar-scanner-cli

# Sử dụng SonarScanner cài đặt trực tiếp
export PATH=$PATH:$(pwd)/sonar-scanner-4.8.0.2856-linux/bin

# Đường dẫn tuyệt đối đến thư mục hiện tại
CURRENT_DIR=$(pwd)

# -Dsonar.externalIssuesReportPaths=${CURRENT_DIR}/laravel-sonar-rules/issues.json \
# -Dsonar.sources=./laravel-massige-app \
sonar-scanner \
  -X \
  -Dsonar.projectKey=app_test \
  -Dsonar.sources=./laravel-sonar-rules/laravel-massige-app \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=sqp_591fcf25cfae8d741bb406a5332d6fb4829df73b \
  -Dsonar.php.file.suffixes=php \
  -Dsonar.java.binaries=${CURRENT_DIR}/laravel-sonar-rules/target/classes \
  -Dsonar.verbose=true