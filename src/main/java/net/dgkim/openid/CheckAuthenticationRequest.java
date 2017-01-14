package net.dgkim.openid;

import java.util.Map;
import java.util.logging.Logger;

public class CheckAuthenticationRequest extends Request {
    public static final String OPENID_ASSOC_HANDLE = "openid.assoc_handle";
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private AuthenticationResponse ar;
    private String handle;

    public CheckAuthenticationRequest(Map map, String mode)
            throws OpenIdException {
        super(map, mode);
        this.ar = new AuthenticationResponse(map);
        this.handle = this.ar.getAssociationHandle();
        checkInvariants();
    }

    private void checkInvariants() throws OpenIdException {
        if (this.handle == null)
            throw new OpenIdException("Missing openid.assoc_handle");
    }

    public Response processUsing(ServerInfo si) throws OpenIdException {
        String invalidate = null;
        Store store = si.getStore();
        String nonceStr = this.ar.getNonce();
        if (nonceStr != null) {
            Nonce n = store.findNonce(nonceStr);
            if (n != null) {
                String s = "Nonce has already been checked";
                log.fine(s);
                throw new OpenIdException(s);
            }
            n = store.generateNonce(nonceStr);
            store.saveNonce(n);
        }

        Association assoc = store.findAssociation(this.handle);
        if ((assoc == null) || (assoc.hasExpired())) {
            invalidate = this.handle;
        }
        Crypto crypto = si.getCrypto();

        return new CheckAuthenticationResponse(this.ar, assoc, crypto,
                invalidate);
    }

    public String toString() {
        return "[CheckAuthenticationRequest " + super.toString() + ", handle="
                + this.handle + ", authentication response=" + this.ar + "]";
    }

    Map toMap() {
        Map map = this.ar.toMap();

        map.putAll(super.toMap());

        return map;
    }
}