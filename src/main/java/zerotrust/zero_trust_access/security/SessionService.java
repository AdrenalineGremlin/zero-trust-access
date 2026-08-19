package zerotrust.zero_trust_access.security;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class SessionService {
    private final RedisTemplate<String, String> redisTemplate;

    public String createSession(String username) {
        // generate session token
        String generatedSessionToken = UUID.randomUUID().toString();
        // store token as key and username as value for later lookup
        redisTemplate.opsForValue().set(generatedSessionToken, username, 30, TimeUnit.MINUTES);
        // give token back so it can be later returned to client
        // for future requests
        return generatedSessionToken;
    }

    public String validateSession(String token) {
        // return null if no token found or expired
        if (token == null)
            return null;
        return redisTemplate.opsForValue().get(token);
    }

    public SessionService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
}
