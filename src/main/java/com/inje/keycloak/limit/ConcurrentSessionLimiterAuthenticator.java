package com.inje.keycloak.limit;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

public class ConcurrentSessionLimiterAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(ConcurrentSessionLimiterAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) { context.attempted(); return; }

        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        int max = parseInt(cfg, "maxSessions", 1);
        if (max < 1) { max = 1; } // 안전장치

        String behavior = get(cfg, "behavior", "DENY_NEW").toUpperCase(Locale.ROOT);
        String scope = get(cfg, "scope", "REALM").toUpperCase(Locale.ROOT);

        // --- 조건부 정책(예외/제한) ---
        if (isWhitelistedByRole(context, cfg) || isWhitelistedByGroup(context, cfg)) {
            LOG.debugf("User %s is whitelisted by role/group. Skipping limit.", user.getUsername());
            context.success();
            return;
        }
        if (!isDeviceAllowed(context, cfg)) {
            deny(context, "Device policy disallows login");
            return;
        }
        if (!isWithinHourRange(cfg)) {
            deny(context, "Outside allowed hours");
            return;
        }

        // --- 세션 수 계산 ---
        KeycloakSession ks = context.getSession();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel as = context.getAuthenticationSession();
        ClientModel client = (as != null) ? as.getClient() : null;

        List<UserSessionModel> sessions = ks.sessions().getUserSessionsStream(realm, user)
            .filter(us -> !us.isOffline())
            .collect(Collectors.toList());

        if ("CLIENT".equals(scope) && client != null) {
            sessions = sessions.stream().filter(us ->
                us.getAuthenticatedClientSessions().containsKey(client.getId())
            ).collect(Collectors.toList());
        }

        if (sessions.size() < max) {
            context.success();
            return;
        }

        // --- 제한 동작 ---
        switch (behavior) {
            case "TERMINATE_OLDEST":
                terminateOne(context, sessions, /*oldest*/true);
                context.success();
                break;
            case "TERMINATE_NEWEST":
                terminateOne(context, sessions, /*oldest*/false);
                context.success();
                break;
            case "LOG_ONLY":
                logOnly(context, sessions, max);
                context.success();
                break;
            case "DENY_NEW":
            default:
                deny(context, "Concurrent session limit exceeded");
                break;
        }
    }

    // ===== Helpers =====

    private void terminateOne(AuthenticationFlowContext context, List<UserSessionModel> sessions, boolean oldest) {
        RealmModel realm = context.getRealm();
        KeycloakSession ks = context.getSession();
        UserModel user = context.getUser();
        AuthenticationSessionModel as = context.getAuthenticationSession();
        ClientModel client = as != null ? as.getClient() : null;

        Comparator<UserSessionModel> byRefresh = Comparator.comparingInt(UserSessionModel::getLastSessionRefresh);
        UserSessionModel target = sessions.stream()
            .sorted(oldest ? byRefresh : byRefresh.reversed())
            .findFirst().orElse(null);

        if (target == null) return;

        // scope=CLIENT인 경우엔 해당 클라이언트 세션만 제거(유저세션 전체 삭제 대신)
        String scope = get(context.getAuthenticatorConfig(), "scope", "REALM").toUpperCase(Locale.ROOT);
        if ("CLIENT".equals(scope) && client != null) {
            // 버전에 따라 안전한 제거 방법이 다릅니다.
            // 1) 가장 단순: 해당 client 세션만 분리
            Map<String, AuthenticatedClientSessionModel> acsMap = target.getAuthenticatedClientSessions();
            AuthenticatedClientSessionModel acs = acsMap.get(client.getId());
            if (acs != null) {
                // 일부 버전에선 removeClientSession API가 별도로 있습니다.
                // 없으면 아래처럼 맵에서 제거 + 세션 provider로 정리
                acs.detachFromUserSession(); // 있으면 사용
                acsMap.remove(client.getId());
                LOG.infof("Terminated client session (client=%s) of user=%s, userSession=%s",
                        client.getClientId(), user.getUsername(), safeId(target.getId()));
                audit(context, "TERMINATE_CLIENT_SESSION", target, client);
                return;
            }
        }

        ks.sessions().removeUserSession(realm, target);
        LOG.infof("Terminated user session (oldest=%s) of user=%s, userSession=%s",
                oldest, user.getUsername(), safeId(target.getId()));
        audit(context, oldest ? "TERMINATE_OLDEST" : "TERMINATE_NEWEST", target, client);
    }

    private void logOnly(AuthenticationFlowContext context, List<UserSessionModel> sessions, int max) {
        UserModel user = context.getUser();

        // ① LOGIN 이벤트에 디테일만 추가 (여기서 success() 호출 금지!)
        context.getEvent()
               .detail("csl_action", "LOG_ONLY_LIMIT_EXCEEDED")
               .detail("csl_current_sessions", String.valueOf(sessions.size()))
               .detail("csl_max", String.valueOf(max));

        // ② 운영 로그만 남김
        LOG.warnf("LOG_ONLY: user=%s exceeded concurrent session limit (current=%d, max=%d)",
                  user != null ? user.getUsername() : "unknown", sessions.size(), max);

        // ③ 로그인은 정상 흐름 → 위에서 context.success() 호출하는 쪽으로 복귀
    }

    private void deny(AuthenticationFlowContext context, String reason) {
        UserModel user = context.getUser();
        EventBuilder ev = context.getEvent().user(user);
        ev.detail("concurrent-session-limiter", "deny").error(Errors.NOT_ALLOWED);

        String redirect = get(context.getAuthenticatorConfig(), "redirectOnDeny", "");
        String message = get(context.getAuthenticatorConfig(), "errorMessage",
                "세션 동시 접속 한도를 초과했습니다.");

        // Browser Flow면 사용자 친화 처리 (Redirect > 메시지)
        if (redirect != null && !redirect.isBlank()) {
            Response resp = Response.status(302).header("Location", redirect).build();
            context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED, resp);
        } else {
            Response resp = Response.status(Response.Status.FORBIDDEN)
                    .entity(message).type("text/plain; charset=UTF-8").build();
            context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED, resp);
        }

        LOG.warnf("DENY_NEW: user=%s, reason=%s", user != null ? user.getUsername() : "unknown", reason);
    }

    private boolean isWhitelistedByRole(AuthenticationFlowContext context, AuthenticatorConfigModel cfg) {
        String csv = get(cfg, "roleWhitelist", "").trim();
        if (csv.isEmpty()) return false;
        Set<String> want = Arrays.stream(csv.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
        if (want.isEmpty()) return false;

        for (RoleModel role : context.getUser().getRoleMappingsStream().collect(Collectors.toSet())) {
            if (want.contains(role.getName())) return true;
        }
        return false;
    }

    private boolean isWhitelistedByGroup(AuthenticationFlowContext context, AuthenticatorConfigModel cfg) {
        String csv = get(cfg, "groupWhitelist", "").trim();
        if (csv.isEmpty()) return false;
        Set<String> want = Arrays.stream(csv.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
        if (want.isEmpty()) return false;

        KeycloakSession ks = context.getSession();
        RealmModel realm = context.getRealm();

        return context.getUser().getGroupsStream().anyMatch(g -> {
            // 1) 이름 매칭
            if (want.contains(g.getName())) return true;
            // 2) 경로 매칭 (getPath() 없는 버전 호환)
            String path = buildGroupPath(ks, realm, g);
            return path != null && want.contains(path);
        });
    }

    private boolean isDeviceAllowed(AuthenticationFlowContext context, AuthenticatorConfigModel cfg) {
        String policy = get(cfg, "devicePolicy", "ALL").toUpperCase(Locale.ROOT);
        if ("ALL".equals(policy)) return true;

        String ua = Optional.ofNullable(context.getHttpRequest())
                .map(r -> r.getHttpHeaders().getHeaderString("User-Agent"))
                .orElse("").toLowerCase(Locale.ROOT);

        boolean isMobile = ua.contains("iphone") || ua.contains("android") || ua.contains("mobile");
        if ("DESKTOP_ONLY".equals(policy)) return !isMobile;
        if ("MOBILE_ONLY".equals(policy))  return  isMobile;
        return true;
    }

    private String buildGroupPath(KeycloakSession ks, RealmModel realm, GroupModel g) {
        // /parent/child 형태의 경로를 수동으로 구성
        Deque<String> parts = new ArrayDeque<>();
        GroupModel cur = g;
        int guard = 0; // 혹시 모를 순환 보호
        while (cur != null && guard++ < 32) {
            parts.addFirst(cur.getName());
            String parentId = cur.getParentId(); // 버전별로 getParentId()는 존재
            if (parentId == null) break;
            cur = realm.getGroupById(parentId);  // 부모를 ID로 조회
        }
        return "/" + String.join("/", parts);
    }

    private boolean isWithinHourRange(AuthenticatorConfigModel cfg) {
        String range = get(cfg, "hourRange", "").trim();
        if (range.isEmpty()) return true;
        String tz = get(cfg, "tz", "Asia/Seoul");
        ZoneId zone = ZoneId.of(tz);

        try {
            String[] parts = range.split("-");
            LocalTime from = LocalTime.parse(parts[0].trim());
            LocalTime to   = LocalTime.parse(parts[1].trim());
            LocalTime now  = LocalTime.now(zone);

            if (from.equals(to)) return true;            // 24시간 허용
            if (from.isBefore(to)) return ! (now.isBefore(from) || now.isAfter(to));
            // 야간 횡단(예: 22:00-06:00)
            return now.isAfter(from) || now.isBefore(to);
        } catch (Exception e) {
            LOG.warnf("Invalid hourRange: %s", range);
            return true; // 파싱 실패 시 제한하지 않음
        }
    }

    private void audit(AuthenticationFlowContext context, String action,
                       UserSessionModel userSession, ClientModel client) {
        // 기존: ev.success();  <-- 제거!
        context.getEvent()
               .detail("csl_action", action);
        if (userSession != null) context.getEvent().detail("user_session_id", safeId(userSession.getId()));
        if (client != null)      context.getEvent().detail("client_id", client.getClientId());
        // success()는 호출하지 않음 (최종 LOGIN 시 합쳐서 기록되도록)
    }

    private String safeId(String id) {
        if (id == null) return "null";
        if (id.length() <= 8) return id;
        return id.substring(0,4) + "…"+ id.substring(id.length()-4);
    }

    private int parseInt(AuthenticatorConfigModel cfg, String key, int def) {
        try { return Integer.parseInt(get(cfg, key, String.valueOf(def))); }
        catch (Exception e) { return def; }
    }
    private String get(AuthenticatorConfigModel cfg, String key, String def) {
        if (cfg == null || cfg.getConfig() == null) return def;
        return cfg.getConfig().getOrDefault(key, def);
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
