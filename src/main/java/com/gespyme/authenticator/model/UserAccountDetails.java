package com.gespyme.authenticator.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.gespyme.authenticator.security.RolePermissions;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@AllArgsConstructor
public class UserAccountDetails {
    private String email;
    private String password;
    private RolePermissions role;
    private LocalDateTime lastTimeLoggedIn;
    private LocalDateTime creationDate;
    private LocalDateTime lastModificationDate;
}
