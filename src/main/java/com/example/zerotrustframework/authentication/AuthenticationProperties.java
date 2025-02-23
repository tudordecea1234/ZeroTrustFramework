package com.example.zerotrustframework.authentication;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "zero-trust.auth")
public class AuthenticationProperties {
    private boolean enabled = true;
    private String issuerUri;
    private String audience;
    private String secretKey;
    private String publicKeyLocation;

    public boolean isEnabled() {
        return enabled;
    }
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuerUri() {
        return issuerUri;
    }
    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getAudience() {
        return audience;
    }
    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getSecretKey() {
        return secretKey;
    }
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getPublicKeyLocation() {
        return publicKeyLocation;
    }
    public void setPublicKeyLocation(String publicKeyLocation) {
        this.publicKeyLocation = publicKeyLocation;
    }
}
