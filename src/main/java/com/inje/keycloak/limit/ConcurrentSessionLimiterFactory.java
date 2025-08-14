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
import java.util.List;

public class ConcurrentSessionLimiterFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String ID = "concurrent-session-limiter";

    private static final ProviderConfigProperty MAX =
            new ProviderConfigProperty("maxSessions","Max sessions per user",
                    "동시 허용 세션 수", ProviderConfigProperty.STRING_TYPE, "1");

    private static final ProviderConfigProperty BEHAVIOR =
            new ProviderConfigProperty("behavior","Behavior on limit",
                    "DENY_NEW 또는 TERMINATE_OLDEST", ProviderConfigProperty.LIST_TYPE, "DENY_NEW");

    private static final ProviderConfigProperty SCOPE =
            new ProviderConfigProperty("scope","Scope",
                    "REALM 또는 CLIENT 기준", ProviderConfigProperty.LIST_TYPE, "REALM");

    private static final List<ProviderConfigProperty> CONFIG = new ArrayList<>();
    static {
        BEHAVIOR.setOptions(List.of("DENY_NEW","TERMINATE_OLDEST"));
        SCOPE.setOptions(List.of("REALM","CLIENT"));
        CONFIG.add(MAX); CONFIG.add(BEHAVIOR); CONFIG.add(SCOPE);
    }

    private static final Requirement[] REQUIREMENT_CHOICES = new Requirement[] {
            Requirement.REQUIRED, Requirement.DISABLED
    };

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "User concurrent session limiter"; }
    @Override public String getHelpText() { return "사용자 동시 세션 수 제한"; }
    @Override public boolean isConfigurable() { return true; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return CONFIG; }
    @Override public Requirement[] getRequirementChoices() { return REQUIREMENT_CHOICES; }
    @Override public boolean isUserSetupAllowed() { return false; }

    // ▼ 24.0.1에서 요구됨
    @Override public String getReferenceCategory() { return "limit"; }
    public String getDisplayCategory()  { return "Session"; }

    @Override public Authenticator create(KeycloakSession session) {
        return new ConcurrentSessionLimiterAuthenticator();
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory f) {}
    @Override public void close() {}
}
