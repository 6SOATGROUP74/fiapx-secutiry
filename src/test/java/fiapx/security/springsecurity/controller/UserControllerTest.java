package fiapx.security.springsecurity.controller;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

import fiapx.security.springsecurity.controller.dto.CreateUserDto;
import fiapx.security.springsecurity.controller.dto.UserResponse;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @InjectMocks
    private UserController userController;

    private User user;
    private Role basicRole;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        basicRole = new Role();
        basicRole.setName("BASIC");

        user = new User();
        user.setUserId(userId);
        user.setUsername("testuser");
        user.setPassword("encodedPassword");
        user.setEmail("test@example.com");
        user.setRoles(Set.of(basicRole));
    }

    @Test
    void whenCreatingNewUser_thenUserIsSaved() {
        CreateUserDto dto = new CreateUserDto("testuser", "password123", "test@example.com");

        when(roleRepository.findByName("BASIC")).thenReturn(basicRole);
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123")).thenReturn("hashedPassword");

        ResponseEntity<Void> response = userController.newUser(dto);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void whenCreatingExistingUser_thenThrowsException() {
        CreateUserDto dto = new CreateUserDto("testuser", "password123", "test@example.com");

        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(user));

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> userController.newUser(dto));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, exception.getStatusCode());
    }

    @Test
    void whenFetchingExistingUser_thenReturnsUser() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        ResponseEntity<UserResponse> response = userController.getUser(userId.toString());

        assertNotNull(response.getBody());
        assertEquals("testuser", response.getBody().nome());
        assertEquals("test@example.com", response.getBody().email());
    }

    @Test
    void whenFetchingNonExistingUser_thenThrowsException() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> userController.getUser(userId.toString()));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, exception.getStatusCode());
    }

    @Test
    void whenListingUsers_thenReturnsAllUsers() {
        List<User> users = List.of(user);
        when(userRepository.findAll()).thenReturn(users);

        ResponseEntity<List<User>> response = userController.listUsers();

        assertEquals(1, response.getBody().size());
        assertEquals("testuser", response.getBody().get(0).getUsername());
    }
}
