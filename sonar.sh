#!/bin/bash

# Sử dụng Docker
# docker run --rm -e SONAR_HOST_URL="http://127.0.0.1:9000" \
#   -e SONAR_SCANNER_OPTS="-Dsonar.token=your_sonar_token" \
#   -v "$(pwd):/usr/src" sonarsource/sonar-scanner-cli

# Sử dụng SonarScanner cài đặt trực tiếp
export PATH=$PATH:$(pwd)/sonar-scanner-4.8.0.2856-linux/bin

sonar-scanner \
  -Dsonar.projectKey=app_test \
  -Dsonar.sources=./typescript-super-error \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.login=sqp_007c72c1b10c1a33672d7e9fc08d8d3776900d55