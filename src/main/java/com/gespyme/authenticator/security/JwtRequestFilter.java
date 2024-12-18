package com.gespyme.authenticator.security;

import com.gespyme.authenticator.auth.TokenExtractor;
import com.gespyme.commons.exeptions.ForbiddenException;
import com.gespyme.commons.exeptions.UnauthorizedException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
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

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

  private static final List<String> allowedUrls = List.of("/login");

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
      performSecurityOperations(request, response, chain);
  }

  private void performSecurityOperations(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (filterAllowedUrls(request)) {
      chain.doFilter(request, response);
      return;
    }

    String token = getJwtToken(request);
    validateToken(token);
    String user = TokenExtractor.getSubject(token);
    String role = TokenExtractor.getRole(token);
    if (shouldAuthenticateUser(user, role, request.getRequestURI(), request.getMethod())) {
      setAuthenticationIsSpringSecurityContext(user, role, token, request);
      chain.doFilter(request, response);
      return;
    }
    throw new ForbiddenException("User not authorized to perform the operation");
  }

  private boolean filterAllowedUrls(HttpServletRequest request)
      throws IOException, ServletException {
    return allowedUrls.stream().anyMatch(url -> url.equals(request.getRequestURI()));
  }

  private boolean shouldAuthenticateUser(String user, String role, String path, String method) {
    return user != null
        && SecurityContextHolder.getContext().getAuthentication() == null
        && isAllowedUser(role, path, method);
  }

  private boolean isAllowedUser(String role, String path, String method) {
    try {
      return RolePermissions.valueOf(role).isAllowed(path, method);
    } catch (IllegalArgumentException e) {
      throw new ForbiddenException("Invalid role");
    }
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

  private void setAuthenticationIsSpringSecurityContext(String user, String role, String token, HttpServletRequest request) {
    UserDetails userDetails =
        new User(user, "", Collections.singletonList(new SimpleGrantedAuthority(role)));
    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
        new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    usernamePasswordAuthenticationToken.setDetails(
        new WebAuthenticationDetailsSource().buildDetails(request));
    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
  }
}
