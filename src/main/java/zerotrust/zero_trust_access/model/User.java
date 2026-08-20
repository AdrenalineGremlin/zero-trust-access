package zerotrust.zero_trust_access.model;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "app_user")
public class User {
    @Id
    @GeneratedValue
    private UUID id;
    @Column(unique = true)
    private String username;
    private String passwordHash;
    // device last verified from, compared against new request to detect new device
    private String knownDeviceId;
    private String knownLocation;
    // to decide if too much time passed after last passed verification
    private Instant lastVerifiedAt;
    // shared secret for validating totp, asgnd at reg
    private String totpSecret;
}
