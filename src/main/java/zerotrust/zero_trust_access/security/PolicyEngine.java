package zerotrust.zero_trust_access.security;

import zerotrust.zero_trust_access.model.RiskContext;
import zerotrust.zero_trust_access.model.RiskLevel;
import zerotrust.zero_trust_access.model.User;

import java.time.Duration;

import org.springframework.stereotype.Service;

@Service
public class PolicyEngine {
    // compute trust score
    public RiskLevel evalRisk(User user, RiskContext riskContext) {
        boolean locationCheck = user.getKnownLocation() == null
                || !user.getKnownLocation().equals(riskContext.getLocation());
        boolean deviceCheck = user.getKnownDeviceId() == null
                || !user.getKnownDeviceId().equals(riskContext.getDeviceID());
        boolean lastVerifiedAt = user.getLastVerifiedAt() == null
                || Duration.between(user.getLastVerifiedAt(), riskContext.getTimestamp()).toMinutes() > 30;
        // unknown device, unknown location, too much time passed after veri
        // = immediate medium risklevel
        if (locationCheck || deviceCheck || lastVerifiedAt)
            return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
}
