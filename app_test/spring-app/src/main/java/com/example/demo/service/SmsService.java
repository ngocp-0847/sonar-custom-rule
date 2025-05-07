package com.example.demo.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class SmsService {
    
    private static final Logger logger = LoggerFactory.getLogger(SmsService.class);
    
    /**
     * Simule l'envoi d'un SMS contenant un code OTP
     */
    public void sendOTP(String phoneNumber, String otpCode) {
        // Dans une application réelle, vous utiliseriez un service d'envoi de SMS
        // comme Twilio, Nexmo, etc.
        String message = "Votre code de vérification est: " + otpCode;
        
        // Simulation d'envoi de SMS pour développement
        logger.info("SMS envoyé au numéro {} avec le message: {}", phoneNumber, message);
    }
}