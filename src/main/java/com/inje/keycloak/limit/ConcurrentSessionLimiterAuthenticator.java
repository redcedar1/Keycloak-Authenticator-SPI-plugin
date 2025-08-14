package com.inje.keycloak.limit;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class ConcurrentSessionLimiterAuthenticator implements Authenticator {

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    // Password(자격 검증) 뒤 스텝에서 실행되도록 배치
    UserModel user = context.getUser();
    if (user == null) { context.attempted(); return; }

    AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
    int max = parseInt(cfg, "maxSessions", 1);
    String behavior = get(cfg, "behavior", "DENY_NEW");
    String scope = get(cfg, "scope", "REALM");

    KeycloakSession ks = context.getSession();
    RealmModel realm = context.getRealm();
    AuthenticationSessionModel as = context.getAuthenticationSession();
    ClientModel client = as != null ? as.getClient() : null;

    // 현재 사용자 세션 조회
    List<UserSessionModel> sessions = ks.sessions().getUserSessionsStream(realm, user)
        .filter(us -> !us.isOffline())
        .collect(Collectors.toList());

    // CLIENT 스코프일 경우, 같은 클라이언트의 세션만 필터링
    if ("CLIENT".equalsIgnoreCase(scope) && client != null) {
      sessions = sessions.stream().filter(us ->
          us.getAuthenticatedClientSessions().containsKey(client.getId())
      ).collect(Collectors.toList());
    }

    if (sessions.size() < max) {
      context.success();
      return;
    }

    if ("TERMINATE_OLDEST".equalsIgnoreCase(behavior)) {
      sessions.stream()
          .sorted(Comparator.comparingLong(UserSessionModel::getStarted)) // 오래된 순
          .findFirst()
          .ifPresent(oldest -> ks.sessions().removeUserSession(realm, oldest));
      context.success(); // 새 로그인 허용
    } else {
      // DENY_NEW
      context.getEvent().user(user);
      context.getEvent().error(Errors.NOT_ALLOWED);
      context.failure(AuthenticationFlowError.ACCESS_DENIED);
    }
  }

  private static int parseInt(AuthenticatorConfigModel cfg, String key, int def) {
    try { return Integer.parseInt(get(cfg, key, String.valueOf(def))); }
    catch (Exception e) { return def; }
  }
  private static String get(AuthenticatorConfigModel cfg, String key, String def) {
    if (cfg == null || cfg.getConfig() == null) return def;
    return cfg.getConfig().getOrDefault(key, def);
  }

  @Override public void action(AuthenticationFlowContext context) {}
  @Override public boolean requiresUser() { return false; }
  @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
  @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) {}
  @Override public void close() {}
}
