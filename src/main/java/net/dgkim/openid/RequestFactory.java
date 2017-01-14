package net.dgkim.openid;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.logging.Logger;

public class RequestFactory {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    public static String OPENID_MODE = "openid.mode";
    public static String ASSOCIATE_MODE = "associate";
    public static String CHECKID_IMMEDIATE_MODE = "checkid_immediate";
    public static String CHECKID_SETUP_MODE = "checkid_setup";
    public static String CHECK_AUTHENTICATION_MODE = "check_authentication";

    public static Request parse(String query)
            throws UnsupportedEncodingException, OpenIdException {
        Map map;
        try {
            map = parseQuery(query);
        } catch (UnsupportedEncodingException e) {
            throw new OpenIdException("Error parsing " + query + ": "
                    + e.toString());
        }

        String s = (String) map.get(OPENID_MODE);
        if (ASSOCIATE_MODE.equals(s)) {
            return new AssociationRequest(map, s);
        }
        if ((CHECKID_IMMEDIATE_MODE.equals(s))
                || (CHECKID_SETUP_MODE.equals(s))) {
            return new AuthenticationRequest(map, s);
        }
        if (CHECK_AUTHENTICATION_MODE.equals(s)) {
            return new CheckAuthenticationRequest(map, s);
        }
        throw new OpenIdException("Cannot parse request from " + query);
    }

    public static Map parseQuery(String query)
            throws UnsupportedEncodingException {
        return MessageParser.urlEncodedToMap(query);
    }
}