package fiapx.security.springsecurity.controller;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import fiapx.security.springsecurity.controller.dto.LoginRequest;
import fiapx.security.springsecurity.controller.dto.LoginResponse;
import fiapx.security.springsecurity.entities.Role;
import fiapx.security.springsecurity.entities.User;
import fiapx.security.springsecurity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
class TokenControllerTest {

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @InjectMocks
    private TokenController tokenController;

    private User user;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        user = new User();
        var role = new Role();
        role.setName("ADMIN");
        user.setUserId(UUID.randomUUID());
        user.setUsername("admin");
        user.setPassword("encodedPassword");
        user.setRoles(Set.of(role));

        loginRequest = new LoginRequest("admin", "123");
    }

    @Test
    void whenLoginIsSuccessful_thenReturnsJwtToken() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("123", user.getPassword())).thenReturn(true);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("fiapx-security")
                .subject("1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(500))
                .claim("scope", "ADMIN")
                .build();
        JwtEncoderParameters params = JwtEncoderParameters.from(claimsSet);
        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("mocked-jwt-token");

        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        ResponseEntity<LoginResponse> response = tokenController.login(loginRequest);

        assertNotNull(response.getBody());
        assertEquals("mocked-jwt-token", response.getBody().accessToken());
        assertEquals(500L, response.getBody().expiresIn());
    }

    @Test
    void whenUserDoesNotExist_thenThrowsBadCredentialsException() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> tokenController.login(loginRequest));
    }

    @Test
    void whenPasswordIsIncorrect_thenThrowsBadCredentialsException() {
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("123", user.getPassword())).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> tokenController.login(loginRequest));
    }
}
