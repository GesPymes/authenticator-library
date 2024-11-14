package com.gespyme.authenticator;

import com.gespyme.authenticator.auth.TokenExtractor;
import com.gespyme.commons.exeptions.InternalServerError;
import com.gespyme.commons.exeptions.UnauthorizedException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            perfomSecurityOperations(request, response, chain);
        } catch (Exception e) {
            throw new InternalServerError("Unexpected server error", e);
        }
    }

    private void perfomSecurityOperations(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (("/h2-console".equals(request.getRequestURI()) || "/login".equals(request.getRequestURI()))) {
            chain.doFilter(request, response);
            return;
        }

        String token = getJwtToken(request);
        validateToken(token);
        String user = TokenExtractor.getSubject(token);
        if (user != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            setAuthenticationIsSpringSecurityContext(user, request);
        }
        chain.doFilter(request, response);
    }

    private String getJwtToken(HttpServletRequest request) {
        final String requestTokenHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (requestTokenHeader == null || !requestTokenHeader.startsWith("Bearer ")) {
            logger.warn("JWT Token does not begin with Bearer String");
            throw new UnauthorizedException("JWT Token does not begin with Bearer String");
        }
        return requestTokenHeader.substring(7);
    }

    private void validateToken(String token) {
        if (TokenExtractor.isTokenExpired(token)) {
            throw new UnauthorizedException("JWT Token expired");
        }
    }

    private void setAuthenticationIsSpringSecurityContext(String user, HttpServletRequest request) {
        UserDetails userDetails = new User(user, "", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken
                .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }


}