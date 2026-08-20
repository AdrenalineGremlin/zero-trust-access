package zerotrust.zero_trust_access.controller;

import java.time.Instant;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import zerotrust.zero_trust_access.model.LoginResult;
import zerotrust.zero_trust_access.model.RiskContext;
import zerotrust.zero_trust_access.DTO.AuthRequest;
import zerotrust.zero_trust_access.DTO.LoginRequest;
import zerotrust.zero_trust_access.DTO.MfaRequest;
import zerotrust.zero_trust_access.service.AuthService;

// controller gets http request, extracts data from request
// hand data to service and package anything that comes back,
// into http response
@RestController
// sets shared url prefix for every endpoint
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;

    // postmapping for creating
    @PostMapping("/register")
    public String register(@RequestBody AuthRequest request) {
        return authService.registUser(request.getUsername(), request.getRawpassword());
    }

    // postmapping for creating
    @PostMapping("/login")
    public LoginResult login(@RequestBody LoginRequest request) {
        RiskContext riskContext = new RiskContext(request.getDeviceId(), request.getLocation(), Instant.now());
        return authService.loginResult(request.getUsername(), request.getRawPassword(), riskContext);
    }

    //// postmapping for creating
    @PostMapping("/verify-mfa")
    public LoginResult verifyMfa(@RequestBody MfaRequest request) {
        RiskContext riskContext = new RiskContext(request.getDeviceId(), request.getLocation(), Instant.now());
        return authService.verifyMfa(request.getUsername(), request.getCode(), riskContext);
    }

    public AuthController(AuthService authService) {
        this.authService = authService;
    }
}