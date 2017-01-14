package net.dgkim.openid;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

public class CheckAuthenticationResponse extends Response {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private boolean isValid;
    static String OPENID_MODE = "openid.mode";
    static String OPENID_NS = "ns";
    static String OPENID_ERROR = "error";
    public static String OPENID_IS_VALID = "is_valid";
    public static final String OPENID_INVALIDATE_HANDLE = "invalidate_handle";
    private AuthenticationResponse ar;
    private Map map;
    private String invalidateHandle;

    public CheckAuthenticationResponse(Map map) {
        super(map);
        Set set = map.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if (OPENID_MODE.equals(key)) {
                this.mode = value;
            } else if (OPENID_IS_VALID.equals(key)) {
                boolean b = false;
                if (value != null) {
                    if (value.equals("true")) {
                        b = true;
                    } else if (value.equals("false")) {
                        b = false;
                    } else {
                        log.severe("No such value: " + value);
                        b = false;
                    }
                }

                log.severe("No such value: " + value);

                this.isValid = b;
            } else if ("invalidate_handle".equals(key)) {
                this.invalidateHandle = value;
            } else if (OPENID_NS.equals(key)) {
                this.ns = value;
            }
        }
    }

    public boolean isValid() {
        return this.isValid;
    }

    public Map toMap() {
        return this.map;
    }

    CheckAuthenticationResponse(AuthenticationResponse ar, Association a,
            Crypto crypto, String invalidateHandle) throws OpenIdException {
        super(Collections.EMPTY_MAP);
        this.ar = ar;
        this.ns = ar.getNamespace();

        this.map = new HashMap();
        if (isVersion2()) {
            this.map.put(OPENID_NS, Message.OPENID_20_NAMESPACE);
        }

        if (a != null) {
            String sig = ar.sign(a.getAssociationType(), a.getMacKey(),
                    ar.getSignedList());

            this.isValid = sig.equals(ar.getSignature());
        } else {
            this.isValid = false;
        }
        if (!(isVersion2())) {
            this.map.put(OPENID_MODE, "id_res");
        }
        this.map.put(OPENID_IS_VALID, (this.isValid) ? "true" : "false");

        if (invalidateHandle != null)
            this.map.put("invalidate_handle", invalidateHandle);
    }

    public String toString() {
        return "[CheckAuthenticationResponse " + super.toString()
                + ", is valid=" + this.isValid + ", authentication response="
                + this.ar + "]";
    }

    public String getInvalidateHandle() {
        return this.invalidateHandle;
    }
}