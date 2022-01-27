package org.sid.SecurityService.Sec.Services;

import org.sid.SecurityService.Sec.Entities.AppRole;
import org.sid.SecurityService.Sec.Entities.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username , String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
