package net.dgkim.openid;

import java.util.Map;
import java.util.logging.Logger;

public abstract class Request extends Message {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    Request(Map map, String mode) {
        this.mode = mode;

        if (map != null)
            this.ns = ((String) map.get(Message.OPENID_NS));
    }

    Map toMap() {
        return super.toMap();
    }

    public abstract Response processUsing(ServerInfo paramServerInfo)
            throws OpenIdException;
}