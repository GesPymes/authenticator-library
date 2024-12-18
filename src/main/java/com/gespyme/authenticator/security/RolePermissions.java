package com.gespyme.authenticator.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;

import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public enum RolePermissions {
  ADMIN(
      Map.of(
          "/customer", allMethodsList(),
          "/user", allMethodsList(),
          "/employee", allMethodsList(),
          "/invoice", allMethodsList(),
          "/job", allMethodsList(),
          "/calendar", allMethodsList(),
          "/appointment", allMethodsList())),

  SYSTEM(
      Map.of(
          "/invoice", allMethodsList(),
          "/job", allMethodsList())),

  USER(
      Map.of(
          "/customer", readPermissions(),
          "/user", readAndModifyPermissions(),
          "/employee", readPermissions(),
          "/job", readAndModifyPermissions()));

  private final Map<String, List<HttpMethod>> urlsAllowed;

  public boolean isAllowed(final String url, String method) {
    return urlsAllowed.entrySet().stream()
        .filter(entry -> url.startsWith(entry.getKey()))
        .map(entry -> entry.getValue().contains(HttpMethod.valueOf(method)))
        .findFirst()
        .orElse(false);
  }

  private static List<HttpMethod> allMethodsList() {
    return List.of(
        HttpMethod.DELETE,
        HttpMethod.GET,
        HttpMethod.DELETE,
        HttpMethod.POST,
        HttpMethod.GET,
        HttpMethod.PATCH);
  }

  private static List<HttpMethod> readPermissions() {
    return List.of(HttpMethod.GET);
  }

  private static List<HttpMethod> readAndModifyPermissions() {
    return List.of(HttpMethod.GET, HttpMethod.PATCH);
  }
}
