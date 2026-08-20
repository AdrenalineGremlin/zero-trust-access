package zerotrust.zero_trust_access.service;

import zerotrust.zero_trust_access.model.LoginResult;
import zerotrust.zero_trust_access.model.RiskContext;
import zerotrust.zero_trust_access.model.RiskLevel;
import zerotrust.zero_trust_access.model.User;
import zerotrust.zero_trust_access.repository.UserRepository;
import zerotrust.zero_trust_access.security.MfaService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import zerotrust.zero_trust_access.security.PolicyEngine;
import zerotrust.zero_trust_access.security.SessionService;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final MfaService mfaService;
    private final PasswordEncoder passwordEncoder;
    private final PolicyEngine policyEngine;
    private final SessionService sessionService;

    public String registUser(String userName, String rawPassword) {
        // hash pass
        String hashedPass = passwordEncoder.encode(rawPassword);
        // generate totpsecret
        String totpSecret = mfaService.generateSecret();
        // register user object
        User user = new User(null, userName, hashedPass, null, null, null, totpSecret);
        // return saved user
        User savedUser = userRepository.save(user);
        return savedUser.getTotpSecret();
    }

    public LoginResult loginResult(String userName, String rawPassword, RiskContext riskContext) {

        User lookUp = userRepository.findByUsername(userName).orElseThrow();
        // check if pass mathces hash
        boolean checkPass = passwordEncoder.matches(rawPassword, lookUp.getPasswordHash());

        if (checkPass) {
            // if true eval risk
            RiskLevel riskLevel = policyEngine.evalRisk(lookUp, riskContext);
            if (riskLevel == RiskLevel.LOW) {
                // updating deviceid,location,verfiedat when low risk to keep familiarity
                // and prevent mfa from triggering ever login
                lookUp.setKnownDeviceId(riskContext.getDeviceID());
                lookUp.setKnownLocation(riskContext.getLocation());
                lookUp.setLastVerifiedAt(riskContext.getTimestamp());
                userRepository.save(lookUp);
                // if low create session and return result
                String token = sessionService.createSession(userName);
                return new LoginResult(RiskLevel.LOW, token);
            } else {
                // if anything else return result with no tkn
                return new LoginResult(riskLevel, null);
            }
        }
        throw new RuntimeException("Invalid Credentials");
    }

    // decides if needs further proof
    public LoginResult verifyMfa(String userName, String totpCode, RiskContext riskContext) {

        User lookUp = userRepository.findByUsername(userName).orElseThrow();
        boolean validateCode = mfaService.validateCode(lookUp.getTotpSecret(), totpCode);

        if (validateCode) {
            // updating deviceid,location,verfiedat when low risk to keep familiarity
            lookUp.setKnownDeviceId(riskContext.getDeviceID());
            lookUp.setKnownLocation(riskContext.getLocation());
            lookUp.setLastVerifiedAt(riskContext.getTimestamp());
            userRepository.save(lookUp);
            String token = sessionService.createSession(userName);
            return new LoginResult(RiskLevel.LOW, token);
        }

        throw new RuntimeException("Invalid Credentials");
    }

    public AuthService(UserRepository userRepository, MfaService mfaService, PasswordEncoder passwordEncoder,
            PolicyEngine policyEngine, SessionService sessionService) {
        this.mfaService = mfaService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.policyEngine = policyEngine;
        this.sessionService = sessionService;
    }
}
