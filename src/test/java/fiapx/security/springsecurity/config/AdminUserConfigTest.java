package fiapx.security.springsecurity.config;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import fiapx.security.springsecurity.entities.Role;
import fiapx.security.springsecurity.entities.User;
import fiapx.security.springsecurity.repository.RoleRepository;
import fiapx.security.springsecurity.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;
import java.util.Set;

@ExtendWith(MockitoExtension.class)
class AdminUserConfigTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @InjectMocks
    private AdminUserConfig adminUserConfig;

    private Role adminRole;
    private User existingAdmin;

    @BeforeEach
    void setUp() {
        adminRole = new Role();
        adminRole.setName("ADMIN");

        existingAdmin = new User();
        existingAdmin.setUsername("admin");
        existingAdmin.setPassword("encodedPassword");
        existingAdmin.setRoles(Set.of(adminRole));
    }

    @Test
    void whenAdminExists_thenShouldNotCreateNewUser() throws Exception {
        when(roleRepository.findByName("ADMIN")).thenReturn(adminRole);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.of(existingAdmin));

        adminUserConfig.run();

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void whenAdminDoesNotExist_thenShouldCreateNewUser() throws Exception {
        when(roleRepository.findByName("ADMIN")).thenReturn(adminRole);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("123")).thenReturn("hashedPassword");

        adminUserConfig.run();

        verify(userRepository).save(argThat(user ->
                user.getUsername().equals("admin") &&
                        user.getPassword().equals("hashedPassword") &&
                        user.getRoles().contains(adminRole)
        ));
    }

    @Test
    void whenCreatingNewAdmin_thenPasswordShouldBeEncoded() throws Exception {
        when(roleRepository.findByName("ADMIN")).thenReturn(adminRole);
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("123")).thenReturn("hashedPassword");

        adminUserConfig.run();

        verify(passwordEncoder).encode("123");
    }
}
