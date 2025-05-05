package com.example.demo.service;

import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
    /**
     * Mock implementation of an email service
     * In a real application, this would use JavaMailSender or similar
     */
    public void sendPasswordResetEmail(String email, String resetUrl) {
        // In a real application, this would send an actual email
        System.out.println("Sending password reset email to: " + email);
        System.out.println("Reset URL: " + resetUrl);
    }
}