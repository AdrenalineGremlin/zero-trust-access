package zerotrust.zero_trust_access.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import zerotrust.zero_trust_access.model.User;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    // optional used for either the username exist or doesnt
    Optional<User> findByUsername(String username);
}
