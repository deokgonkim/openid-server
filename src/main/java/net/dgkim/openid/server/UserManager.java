package net.dgkim.openid.server;

public abstract interface UserManager {
    public abstract void remember(String paramString1, String paramString2);

    public abstract String getRememberedUser(String paramString1,
            String paramString2);

    public abstract boolean canClaim(String paramString1, String paramString2);
}