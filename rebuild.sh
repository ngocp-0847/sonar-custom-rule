#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define variables
PROJECT_DIR="laravel-sonar-rules"
JAR_FILE="laravel-custom-rules-1.0.jar"
SONARQUBE_CONTAINER="a5a119b99bff"
SONARQUBE_PLUGIN_PATH="/opt/sonarqube/extensions/plugins/"

# Build the project
echo "Building the project..."
cd "$PROJECT_DIR"
mvn clean compile install
cd ..

# Copy the JAR file to the SonarQube container
echo "Copying JAR file to SonarQube container..."
docker cp "$PROJECT_DIR/target/$JAR_FILE" "$SONARQUBE_CONTAINER:$SONARQUBE_PLUGIN_PATH"

# Restart SonarQube
echo "Restarting SonarQube..."
docker-compose restart sonarqube

# Run SonarScanner
echo "Running SonarScanner..."
docker-compose up sonar-scanner

# Notify user to check analysis results
echo "Analysis completed. Check for SVG security issues in the SonarQube dashboard."