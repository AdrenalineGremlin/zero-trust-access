package zerotrust.zero_trust_access.DTO;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MfaRequest {
    private String username;
    private String code;
    private String deviceId;
    private String location;
}
