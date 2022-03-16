package demo.spring.jwt.repository;

import demo.spring.jwt.entity.ERole;
import demo.spring.jwt.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
