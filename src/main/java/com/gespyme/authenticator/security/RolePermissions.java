package com.gespyme.authenticator.security;

import lombok.RequiredArgsConstructor;

import java.util.List;

@RequiredArgsConstructor
public enum RolePermissions {

  ADMIN(List.of("/customer", "/user", "/employee", "/invoice", "/job")),
  SYSTEM(List.of("/invoice", "/job")),
  USER(List.of("/job"));

  private final List<String> urlsAllowed;

  public boolean isAllowed(final String url) {
    return this.urlsAllowed.stream().anyMatch(url::startsWith);
  }
}
