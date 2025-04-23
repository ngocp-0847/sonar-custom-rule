
cd laravel-sonar-rules && mvn clean compile install
cd ../
docker cp laravel-sonar-rules/target/laravel-custom-rules-1.0.jar a5a119b99bff:/opt/sonarqube/extensions/plugins/

docker-compose restart sonarqube

# Run SonarScanner
docker-compose up sonar-scanner