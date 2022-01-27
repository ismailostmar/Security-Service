package org.sid.SecurityService.Sec.Repository;

import org.sid.SecurityService.Sec.Entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
        AppUser findByUsername(String username);
}
