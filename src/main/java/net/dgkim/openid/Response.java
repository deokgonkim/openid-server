package net.dgkim.openid;

import java.util.Map;
import java.util.logging.Logger;

public abstract class Response extends Message {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    static String OPENID_ERROR = "error";
    String error;

    private void $init$() {
        this.error = null;
    }

    String getError() {
        return this.error;
    }

    Map toMap() {
        return super.toMap();
    }

    Response(Map map) {
        $init$();
        if (map != null) {
            this.ns = ((String) map.get(Message.OPENID_NS));
            this.error = ((String) map.get(OPENID_ERROR));
        }
    }

    public String toString() {
        String s = super.toString();
        if (this.error != null) {
            s = s + ", error=" + this.error;
        }

        return s;
    }
}