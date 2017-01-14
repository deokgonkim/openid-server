package net.dgkim.openid;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Message {
    String mode;
    String ns;
    static String OPENID_20_NAMESPACE = "http://specs.openid.net/auth/2.0";
    static String OPENID_NS = "openid.ns";
    static String OPENID_MODE = "openid.mode";

    static Set OPENID_RESERVED_WORDS = new HashSet(Arrays.asList(new String[] {
            "assoc_handle", "assoc_type", "claimed_id", "contact", "delegate",
            "dh_consumer_public", "dh_gen", "dh_modulus", "error", "identity",
            "invalidate_handle", "mode", "ns", "op_endpoint", "openid",
            "realm", "reference", "response_nonce", "return_to", "server",
            "session_type", "sig", "signed", "trust_root" }));

    public boolean isVersion2() {
        return OPENID_20_NAMESPACE.equals(this.ns);
    }

    public String getNamespace() {
        return this.ns;
    }

    public String toString() {
        String s = "version=";
        if (isVersion2())
            s = s + "2.0";
        else {
            s = s + "1.x";
        }
        if (this.ns != null) {
            s = s + ", namespace=" + this.ns;
        }

        return s;
    }

    public String toPostString() throws OpenIdException {
        return MessageParser.toPostString(this);
    }

    public String toUrlString() throws OpenIdException {
        return MessageParser.toUrlString(this);
    }

    Map toMap() {
        Map map = new HashMap();
        if (this.ns != null) {
            map.put(OPENID_NS, this.ns);
        }
        if (this.mode != null) {
            map.put(OPENID_MODE, this.mode);
        }

        return map;
    }
}