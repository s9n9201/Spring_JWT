package demo.spring.jwt.controllers;

import demo.spring.jwt.entity.ERole;
import demo.spring.jwt.entity.RefreshToken;
import demo.spring.jwt.entity.Role;
import demo.spring.jwt.entity.User;
import demo.spring.jwt.exception.TokenRefreshException;
import demo.spring.jwt.payload.request.LoginRequest;
import demo.spring.jwt.payload.request.SignupRequest;
import demo.spring.jwt.payload.request.TokenRefreshRequest;
import demo.spring.jwt.payload.response.JwtResponse;
import demo.spring.jwt.payload.response.MessageResponse;
import demo.spring.jwt.payload.response.TokenRefreshResponse;
import demo.spring.jwt.repository.RoleRepository;
import demo.spring.jwt.repository.UserRepository;
import demo.spring.jwt.security.jwt.JwtUtils;
import demo.spring.jwt.security.services.RefreshTokenService;
import demo.spring.jwt.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins="*", maxAge=3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        System.out.println("do AuthController signin！");
        Authentication authentication=authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()) );
        System.out.println("--------------------------------");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails=(UserDetailsImpl) authentication.getPrincipal();
        String jwt=jwtUtils.generateJwtToken(userDetails);
        List<String> roles=userDetails.getAuthorities().stream()
                .map(item->{
                    System.out.println("Item > "+item.toString());
                    return item.getAuthority();
                })
                .collect(Collectors.toList());
        RefreshToken refreshToken=refreshTokenService.createRefreshToken(userDetails.getId());
        return ResponseEntity.ok(new JwtResponse(jwt
                                                ,refreshToken.getToken()
                                                ,userDetails.getId()
                                                ,userDetails.getUsername()
                                                ,userDetails.getEmail()
                                                ,roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Username is already taken!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Email is already in use!"));
        }
        User user=new User(signupRequest.getUsername()
                            ,signupRequest.getEmail()
                            ,encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles=signupRequest.getRole();
        Set<Role> roles=new HashSet<>();
        if (strRoles==null) {
            Role userRole=roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role->{
                ERole tmpERol;
                switch (role) {
                    case "admin":
                        tmpERol=ERole.ROLE_ADMIN; break;
                    case "mod":
                        tmpERol=ERole.ROLE_MODERATOR; break;
                    default:
                        tmpERol=ERole.ROLE_USER; break;
                }
                Role userRole=roleRepository.findByName(tmpERol)
                        .orElseThrow(()->new RuntimeException("Role is not found"));
                roles.add(userRole);
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken=request.getRefreshToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user->{
                    String token=jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(()->new TokenRefreshException(requestRefreshToken, "Refresh token is not in database!"));
    }
}
