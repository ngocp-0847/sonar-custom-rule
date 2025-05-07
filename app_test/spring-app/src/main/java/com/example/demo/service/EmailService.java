package com.example.demo.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class EmailService {
    
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);
    
    /**
     * Simule l'envoi d'un email de réinitialisation de mot de passe
     */
    public void sendPasswordResetEmail(String email, String token) {
        // Dans une application réelle, vous utiliseriez JavaMailSender ou un service d'envoi d'email
        String resetUrl = "http://localhost:8080/reset-password?token=" + token;
        String emailContent = "Cliquez sur le lien suivant pour réinitialiser votre mot de passe: " + resetUrl;
        
        // Simulation d'envoi d'email pour développement
        logger.info("Email de réinitialisation envoyé à {} avec le contenu: {}", email, emailContent);
    }
}