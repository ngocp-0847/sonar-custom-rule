package com.mycompany.sonar.rules;

import org.sonar.api.rule.RuleStatus;
import org.sonar.api.rule.Severity;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.server.rule.RulesDefinitionAnnotationLoader;

/**
 * Defines the custom rules for Spring Boot Java code analysis
 */
public class SpringBootCustomRulesDefinition implements RulesDefinition {
    
    public static final String REPOSITORY_KEY = "custom-spring-boot-java";
    public static final String LANGUAGE = "java";
    public static final String NAME = "Spring Boot Custom Rules";
    
    @Override
    public void define(Context context) {
        NewRepository repository = context.createRepository(REPOSITORY_KEY, LANGUAGE)
                                        .setName(NAME);
        
        // Automatically load rule metadata from Rule annotations
        RulesDefinitionAnnotationLoader rulesLoader = new RulesDefinitionAnnotationLoader();
        rulesLoader.load(repository, 
                SpringBootSecureCredentialRecoveryCheck.class);
        
        // Add HTML descriptions for the rule
        setRuleDescriptions(repository);
        
        repository.done();
    }
    
    /**
     * Sets HTML descriptions for all rules in the repository.
     * SonarQube requires either an HTML description or Markdown description for each rule.
     */
    private void setRuleDescriptions(NewRepository repository) {
        // Set description for SpringBootSecureCredentialRecovery rule
        repository.rule("SpringBootSecureCredentialRecovery")
            .setHtmlDescription(
                "<p>This rule detects insecure credential recovery mechanisms in Spring Boot applications.</p>" +
                "<h2>Vulnerability</h2>" +
                "<p>OWASP ASVS V2.5.6 requires that forgotten password and other recovery paths use a secure recovery mechanism. " +
                "Using insecure mechanisms like simple email-based reset links, static secrets, or security questions can lead to account takeover.</p>" +
                "<h2>Risk</h2>" +
                "<p>If an attacker gains access to a user's email or can bypass weak recovery mechanisms like security questions, " +
                "they could potentially reset passwords and take over accounts.</p>" +
                "<h2>Example of non-compliant code</h2>" +
                "<pre>" +
                "@Controller\n" +
                "public class PasswordResetController {\n" +
                "    @Autowired\n" +
                "    private UserService userService;\n" +
                "    \n" +
                "    @Autowired\n" +
                "    private EmailService emailService;\n" +
                "    \n" +
                "    @PostMapping(\"/forgot-password\")\n" +
                "    public String forgotPassword(@RequestParam(\"email\") String email) {\n" +
                "        User user = userService.findByEmail(email);\n" +
                "        if (user != null) {\n" +
                "            String token = UUID.randomUUID().toString();\n" +
                "            userService.createPasswordResetToken(user, token);\n" +
                "            emailService.sendPasswordResetEmail(user.getEmail(), token);\n" +
                "        }\n" +
                "        return \"redirect:/login?resetSent\";\n" +
                "    }\n" +
                "}</pre>" +
                "<h2>Example of compliant code</h2>" +
                "<pre>" +
                "@Controller\n" +
                "public class PasswordResetController {\n" +
                "    @Autowired\n" +
                "    private UserService userService;\n" +
                "    \n" +
                "    @Autowired\n" +
                "    private EmailService emailService;\n" +
                "    \n" +
                "    @Autowired\n" +
                "    private TOTPService totpService;\n" +
                "    \n" +
                "    @PostMapping(\"/forgot-password\")\n" +
                "    public String forgotPassword(@RequestParam(\"email\") String email) {\n" +
                "        User user = userService.findByEmail(email);\n" +
                "        if (user != null) {\n" +
                "            String token = UUID.randomUUID().toString();\n" +
                "            // Generate a time-based OTP code\n" +
                "            String totp = totpService.generateTOTP(user.getSecretKey());\n" +
                "            userService.createPasswordResetToken(user, token, totp);\n" +
                "            emailService.sendPasswordResetEmail(user.getEmail(), token);\n" +
                "            // Send TOTP via separate channel (e.g., SMS)\n" +
                "            smsService.sendOTP(user.getPhone(), totp);\n" +
                "        }\n" +
                "        return \"redirect:/login?resetSent\";\n" +
                "    }\n" +
                "    \n" +
                "    @PostMapping(\"/reset-password\")\n" +
                "    public String resetPassword(\n" +
                "            @RequestParam(\"token\") String token,\n" +
                "            @RequestParam(\"otp\") String otp,\n" +
                "            @RequestParam(\"password\") String newPassword) {\n" +
                "        // Verify both token and time-based OTP\n" +
                "        if (userService.validatePasswordResetToken(token) && \n" +
                "            totpService.validateTOTP(userService.getUserFromToken(token).getSecretKey(), otp)) {\n" +
                "            userService.resetPassword(token, newPassword);\n" +
                "            return \"redirect:/login?resetSuccess\";\n" +
                "        }\n" +
                "        return \"redirect:/reset-password?error\";\n" +
                "    }\n" +
                "}</pre>" +
                "<h2>References</h2>" +
                "<ul>" +
                "  <li>OWASP ASVS v4.0.3: Requirement 2.5.6</li>" +
                "  <li><a href='https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html'>OWASP Forgot Password Cheat Sheet</a></li>" +
                "  <li><a href='https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html'>OWASP Multi-factor Authentication Cheat Sheet</a></li>" +
                "</ul>"
            );
    }
}