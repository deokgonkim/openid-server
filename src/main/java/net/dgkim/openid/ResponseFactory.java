package net.dgkim.openid;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

public class ResponseFactory {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    private static String OPENID_MODE = "openid.mode";
    private static String ASSOCIATE_MODE = "associate";

    public static Response parse(String query) throws OpenIdException {
        Map map;
        try {
            if (MessageParser.numberOfNewlines(query) == 1)
                map = MessageParser.urlEncodedToMap(query);
            else
                map = MessageParser.postedToMap(query);
        } catch (IOException e) {
            throw new OpenIdException("Error parsing " + query + ": "
                    + e.toString());
        }

        Set set = map.keySet();
        if (((set.contains(AssociationResponse.OPENID_SESSION_TYPE)) && (set
                .contains(AssociationResponse.OPENID_ENC_MAC_KEY)))
                || (set.contains(AssociationResponse.OPENID_ASSOCIATION_TYPE))) {
            return new AssociationResponse(map);
        }
        if (set.contains(AuthenticationResponse.OPENID_SIG)) {
            return new AuthenticationResponse(map);
        }
        if (set.contains(CheckAuthenticationResponse.OPENID_IS_VALID)) {
            return new CheckAuthenticationResponse(map);
        }
        throw new OpenIdException("Cannot parse response from " + query);
    }
}