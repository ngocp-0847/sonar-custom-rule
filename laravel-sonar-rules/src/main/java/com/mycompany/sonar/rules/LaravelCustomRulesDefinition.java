package com.mycompany.sonar.rules;

import org.sonar.api.rule.RuleStatus;
import org.sonar.api.rule.Severity;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.server.rule.RulesDefinitionAnnotationLoader;

/**
 * Defines the custom rules for Laravel PHP code analysis
 */
public class LaravelCustomRulesDefinition implements RulesDefinition {
    
    // Must match the repository key in CustomPhpRuleRepository
    public static final String REPOSITORY_KEY = "custom-laravel-php";
    public static final String LANGUAGE = "php";
    public static final String NAME = "Laravel Custom Rules";
    
    @Override
    public void define(Context context) {
        NewRepository repository = context.createRepository(REPOSITORY_KEY, LANGUAGE)
                                          .setName(NAME);
        
        // Automatically load rule metadata from Rule annotations
        RulesDefinitionAnnotationLoader rulesLoader = new RulesDefinitionAnnotationLoader();
        rulesLoader.load(repository, 
                LaravelMassAssignmentCheck.class,
                LaravelPlaintextOTPCheck.class,
                UnsafeSVGContentCheck.class);
        
        // Add HTML descriptions for each rule - this is required by SonarQube
        setRuleDescriptions(repository);
        
        repository.done();
    }
    
    /**
     * Sets HTML descriptions for all rules in the repository.
     * SonarQube requires either an HTML description or Markdown description for each rule.
     */
    private void setRuleDescriptions(NewRepository repository) {
        // Set description for LaravelMassAssignment rule
        repository.rule("LaravelMassAssignment")
            .setHtmlDescription(
                "<p>This rule detects unsafe mass assignment vulnerabilities in Laravel applications.</p>" +
                "<h2>Vulnerability</h2>" +
                "<p>Mass assignment vulnerabilities occur when a user can update model attributes that they shouldn't " +
                "have access to. This can happen when passing user input directly to model creation or update methods.</p>" +
                "<h2>Risk</h2>" +
                "<p>Attackers can potentially modify sensitive fields like 'is_admin' or other security-related " +
                "attributes by manipulating request data.</p>" +
                "<h2>Example of non-compliant code</h2>" +
                "<pre>$user = User::create($request->all());</pre>" +
                "<p>or</p>" +
                "<pre>$user->update($request->all());</pre>" +
                "<h2>Example of compliant code</h2>" +
                "<pre>" +
                "$user = User::create($request->only(['name', 'email', 'password']));" +
                "</pre>" +
                "<p>or define $fillable/$guarded in your model:</p>" +
                "<pre>" +
                "class User extends Model {\n" +
                "    protected $fillable = ['name', 'email', 'password'];\n" +
                "    // or\n" +
                "    protected $guarded = ['is_admin', 'role'];\n" +
                "}</pre>"
            );
            
        // Set description for LaravelPlaintextOTP rule
        repository.rule("LaravelPlaintextOTP")
            .setHtmlDescription(
                "<p>This rule detects plaintext OTP (One-Time Password) storage in Laravel applications.</p>" +
                "<h2>Vulnerability</h2>" +
                "<p>Storing OTPs in plaintext can lead to security breaches if the database, cache, or logs are " +
                "compromised. OTPs should always be stored using secure hashing algorithms.</p>" +
                "<h2>Risk</h2>" +
                "<p>If an attacker gains access to the database, logs, or session storage, they could potentially " +
                "retrieve OTPs and use them to bypass authentication.</p>" +
                "<h2>Example of non-compliant code</h2>" +
                "<pre>" +
                "// Storing plaintext OTP in database\n" +
                "DB::table('otp_table')->insert([\n" +
                "    'user_id' => $userId,\n" +
                "    'otp' => $otp,  // Plaintext OTP\n" +
                "    'created_at' => now()\n" +
                "]);</pre>" +
                "<h2>Example of compliant code</h2>" +
                "<pre>" +
                "// Using hash with salt for OTP storage\n" +
                "DB::table('otp_table')->insert([\n" +
                "    'user_id' => $userId,\n" +
                "    'otp_hash' => Hash::make($otp . $userId),  // Hashed with salt\n" +
                "    'created_at' => now()\n" +
                "]);</pre>"
            );
            
        // Set description for UnsafeSVGContent rule
        repository.rule("UnsafeSVGContent")
            .setHtmlDescription(
                "<p>This rule detects unsanitized SVG content that could lead to XSS vulnerabilities.</p>" +
                "<h2>Vulnerability</h2>" +
                "<p>SVG files can contain executable JavaScript code through &lt;script&gt; tags, event handlers, and " +
                "&lt;foreignObject&gt; elements. When user-supplied SVG content is rendered without proper sanitization, " +
                "it can lead to Cross-Site Scripting (XSS) attacks.</p>" +
                "<h2>Risk</h2>" +
                "<p>Attackers can embed malicious JavaScript within SVG files that executes in the context of your application, " +
                "potentially stealing session cookies, personal data, or performing actions on behalf of the user.</p>" +
                "<h2>Example of non-compliant code</h2>" +
                "<pre>" +
                "// Laravel Blade template\n" +
                "{!! $userSuppliedSvg !!}\n\n" +
                "// React component\n" +
                "function IconDisplay({ svgContent }) {\n" +
                "  return &lt;div dangerouslySetInnerHTML={{ __html: svgContent }} /&gt;;\n" +
                "}\n\n" +
                "// Direct DOM manipulation\n" +
                "element.innerHTML = userUploadedSvgContent;</pre>" +
                "<h2>Example of compliant code</h2>" +
                "<pre>" +
                "// Laravel - use a sanitizer library\n" +
                "use enshrined\\svgSanitize\\Sanitizer;\n\n" +
                "$sanitizer = new Sanitizer();\n" +
                "$cleanSvg = $sanitizer->sanitize($userSuppliedSvg);\n" +
                "{!! $cleanSvg !!}\n\n" +
                "// React - use DOMPurify\n" +
                "import DOMPurify from 'dompurify';\n\n" +
                "function IconDisplay({ svgContent }) {\n" +
                "  const sanitizedSvg = DOMPurify.sanitize(svgContent, { USE_PROFILES: { svg: true } });\n" +
                "  return &lt;div dangerouslySetInnerHTML={{ __html: sanitizedSvg }} /&gt;;\n" +
                "}</pre>" +
                "<h2>References</h2>" +
                "<ul>" +
                "  <li>OWASP ASVS v4.0.3: Requirement 5.2.7</li>" +
                "  <li><a href='https://owasp.org/www-community/attacks/xss/'>OWASP XSS Prevention</a></li>" +
                "  <li><a href='https://github.com/cure53/DOMPurify'>DOMPurify</a></li>" +
                "  <li><a href='https://github.com/darylldoyle/svg-sanitizer'>SVG Sanitizer for PHP</a></li>" +
                "</ul>"
            );
    }
}