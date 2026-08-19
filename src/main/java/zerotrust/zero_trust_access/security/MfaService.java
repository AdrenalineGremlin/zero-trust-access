package zerotrust.zero_trust_access.security;

import org.springframework.stereotype.Service;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

@Service
public class MfaService {
    // generate secret
    public String generateSecret() {
        SecretGenerator secretGenerator = new DefaultSecretGenerator();
        return secretGenerator.generate();
    }

    // validate totp code
    public boolean validateCode(String secret, String code) {
        // TimeProvider because totp code are time-based
        TimeProvider timeGen = new SystemTimeProvider();
        // generates what the code would be now when secret is given
        CodeGenerator codeGen = new DefaultCodeGenerator();
        // compares code against what is should be valid now
        CodeVerifier verifier = new DefaultCodeVerifier(codeGen, timeGen);
        return verifier.isValidCode(secret, code);
    }
}
