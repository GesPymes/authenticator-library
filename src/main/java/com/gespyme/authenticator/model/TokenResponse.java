package com.gespyme.authenticator.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class TokenResponse {
    private String token;
    private boolean isValid;
    private String userId;

}
