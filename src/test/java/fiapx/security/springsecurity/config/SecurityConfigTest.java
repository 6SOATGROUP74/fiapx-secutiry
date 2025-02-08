package fiapx.security.springsecurity.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

    @InjectMocks
    private SecurityConfig securityConfig;

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private RSAPublicKey publicKey;

    @Mock
    private RSAPrivateKey privateKey;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(securityConfig, "publicKey", publicKey);
        ReflectionTestUtils.setField(securityConfig, "privateKey", privateKey);
    }

    @Test
    void testJwtDecoderCreation() {
        JwtDecoder jwtDecoder = securityConfig.jwtDecoder();
        assertNotNull(jwtDecoder);
        assertInstanceOf(NimbusJwtDecoder.class, jwtDecoder);
    }


    @Test
    void testBCryptPasswordEncoderCreation() {
        BCryptPasswordEncoder encoder = securityConfig.bCryptPasswordEncoder();
        assertNotNull(encoder);
        assertInstanceOf(BCryptPasswordEncoder.class, encoder);
    }
}
