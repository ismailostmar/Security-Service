package org.sid.SecurityService.Sec.web;

import org.sid.SecurityService.Sec.Entities.AppUser;
import org.sid.SecurityService.Sec.Services.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService){
        this.accountService=accountService;
    }

    @GetMapping(path = "/users")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }
}
