package com.inje.keycloak.limit;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ConcurrentSessionLimiterFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    //   내장 실행자/이전 버전과 구분되게 ID를 바꾸는 것을 강력 권장
    public static final String ID = "concurrent-session-limiter-enhanced";

    private static final ProviderConfigProperty MAX =
        new ProviderConfigProperty("maxSessions","Max sessions per user",
            "동시 허용 세션 수 (>=1).", ProviderConfigProperty.STRING_TYPE, "1");

    private static final ProviderConfigProperty BEHAVIOR =
        new ProviderConfigProperty("behavior","Behavior on limit",
            "DENY_NEW / TERMINATE_OLDEST / TERMINATE_NEWEST / LOG_ONLY",
            ProviderConfigProperty.LIST_TYPE, "DENY_NEW");

    private static final ProviderConfigProperty SCOPE =
        new ProviderConfigProperty("scope","Scope",
            "REALM 또는 CLIENT 기준", ProviderConfigProperty.LIST_TYPE, "REALM");

    private static final ProviderConfigProperty ROLE_WHITELIST =
        new ProviderConfigProperty("roleWhitelist","Role whitelist (comma)",
            "여기에 나열된 역할을 가진 사용자는 제한 예외 (예: admin,superuser)", ProviderConfigProperty.STRING_TYPE, "");

    private static final ProviderConfigProperty GROUP_WHITELIST =
        new ProviderConfigProperty("groupWhitelist","Group whitelist (comma)",
            "이 그룹(이름 또는 /경로)에 속하면 제한 예외 (예: /Company/Dept,VIP)", ProviderConfigProperty.STRING_TYPE, "");

    private static final ProviderConfigProperty DEVICE_POLICY =
        new ProviderConfigProperty("devicePolicy","Device policy",
            "ALL / DESKTOP_ONLY / MOBILE_ONLY", ProviderConfigProperty.LIST_TYPE, "ALL");

    private static final ProviderConfigProperty TZ =
        new ProviderConfigProperty("tz","Timezone ID",
            "예: Asia/Seoul (미지정 시 서버/JVM 기본)", ProviderConfigProperty.STRING_TYPE, "Asia/Seoul");

    private static final ProviderConfigProperty HOUR_RANGE =
        new ProviderConfigProperty("hourRange","Allowed hour range",
            "허용 시간대. 예: 09:00-18:00 (빈 값이면 항상 허용)", ProviderConfigProperty.STRING_TYPE, "");

    private static final ProviderConfigProperty ERROR_MESSAGE =
        new ProviderConfigProperty("errorMessage","Custom error message",
            "Deny 시 사용자에게 표시할 메시지(브라우저 플로우)", ProviderConfigProperty.STRING_TYPE, "");

    private static final ProviderConfigProperty REDIRECT_URL =
        new ProviderConfigProperty("redirectOnDeny","Redirect URL on deny",
            "설정 시 DENY_NEW에서 해당 URL로 302 리다이렉트(브라우저 플로우)", ProviderConfigProperty.STRING_TYPE, "");

    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>();
    static {

        BEHAVIOR.setOptions(Arrays.asList("DENY_NEW","TERMINATE_OLDEST","TERMINATE_NEWEST","LOG_ONLY"));
        SCOPE.setOptions(Arrays.asList("REALM","CLIENT"));
        DEVICE_POLICY.setOptions(Arrays.asList("ALL","DESKTOP_ONLY","MOBILE_ONLY"));

        CONFIG.add(MAX);
        CONFIG.add(BEHAVIOR);
        CONFIG.add(SCOPE);

        CONFIG.add(ROLE_WHITELIST);
        CONFIG.add(GROUP_WHITELIST);
        CONFIG.add(DEVICE_POLICY);

        CONFIG.add(TZ);
        CONFIG.add(HOUR_RANGE);

        CONFIG.add(ERROR_MESSAGE);
        CONFIG.add(REDIRECT_URL);
    }

    private static final Requirement[] REQUIREMENT_CHOICES = new Requirement[] {
        Requirement.REQUIRED, Requirement.DISABLED
    };

    @Override public String getId() { return ID; }

    @Override public String getDisplayType() {

        return "User concurrent session limiter (Enhanced)";
    }

    @Override public String getHelpText() {
        return "역할/그룹/디바이스/시간대 기반 동시 세션 제한 + 확장 동작";
    }

    @Override public boolean isConfigurable() { return true; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }
    @Override public Requirement[] getRequirementChoices() { return REQUIREMENT_CHOICES; }
    @Override public boolean isUserSetupAllowed() { return false; }

    // Keycloak 24.x에서 요구되는 레퍼런스/카테고리
    @Override public String getReferenceCategory() { return "limit"; }
    public String getDisplayCategory()  { return "Session"; }

    @Override public Authenticator create(KeycloakSession session) {
        return new ConcurrentSessionLimiterAuthenticator();
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory f) {}
    @Override public void close() {}
}
