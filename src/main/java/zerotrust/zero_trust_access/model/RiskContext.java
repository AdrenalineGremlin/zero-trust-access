package zerotrust.zero_trust_access.model;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RiskContext {
    private String deviceID;
    private String location;
    private Instant timestamp;
}
