package net.dgkim.openid.server;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

public class MemoryUserManager implements UserManager {
    private Map userMap;
    private Map rememberMeMap;

    public MemoryUserManager() {
        $init$();
        System.out.println("MemoryUserManager created.");
    }

    private void $init$() {
        this.userMap = new HashMap();
        this.rememberMeMap = new HashMap();
    }

    public User getUser(String username) {
        return ((User) this.userMap.get(username));
    }

    public void save(User user) {
        this.userMap.put(user.getUsername(), user);
    }

    public void remember(String username, String authKey) {
        this.rememberMeMap.put(username, authKey);
    }

    public String getRememberedUser(String username, String authKey) {
        if ((username == null) || (authKey == null)) {
            return null;
        }
        String auth = (String) this.rememberMeMap.get(username);
        if ((auth != null) && (authKey.equals(auth))) {
            return username;
        }

        return null;
    }

    public boolean canClaim(String username, String claimedId) {
        String usernameFromClaimedId = claimedId.substring(claimedId
                .lastIndexOf("/") + 1);

        return (!(username.equals(usernameFromClaimedId)));
    }
}