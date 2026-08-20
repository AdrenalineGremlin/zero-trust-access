package zerotrust.zero_trust_access.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginResult {
    private RiskLevel riskLevel;
    private String sessionToken;
}
