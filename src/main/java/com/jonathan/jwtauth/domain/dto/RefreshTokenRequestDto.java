package com.jonathan.jwtauth.domain.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
/* JsonNaming is redundant since this request is not json, but x-www-form-urlencoded */
//@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class RefreshTokenRequestDto {
    private String grant_type;
    private String refresh_token;
}
