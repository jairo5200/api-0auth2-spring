package com.jb.securityservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {

    @Autowired
    private JwtEncoder jwtEncoder;

    @PostMapping("/token")
    public Map<String,String> generarToken(Authentication authentication){
        Map<String,String> idToken = new HashMap<>();
        Instant instant = Instant.now(); //obtenemos la hora actual

        // convertimos las autoridades en cadena
        String scope = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(""));

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(authentication.getName()) // establecemos el nombre de usuario autenticado
                .issuedAt(instant) // establecemos la hora de mision del token
                // establecemos la fecha de expiracion de jwt 5 minutos a partir de la hora actual
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                .issuer("security service")// emisor del token
                .claim("scope",scope)
                .build();

        String jwtAccesToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccesToken);
        return idToken;
    }
}
