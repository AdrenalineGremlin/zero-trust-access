package zerotrust.zero_trust_access.DTO;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    private String username;
    private String rawPassword;
    private String deviceId;
    private String location;
}
