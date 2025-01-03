package com.gespyme.authenticator.model;

import java.util.List;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Role {

  ADMIN(List.of("/customer", "/user", "/employee", "/invoice", "/job")),
  SYSTEM(List.of("/invoice", "/job")),
  USER(List.of("/job"));

  private final List<String> urlsAllowed;

  public boolean isAllowed(final String url) {
    return this.urlsAllowed.stream().anyMatch(url::startsWith);
  }
}
