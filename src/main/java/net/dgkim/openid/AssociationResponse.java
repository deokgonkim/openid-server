package net.dgkim.openid;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

public class AssociationResponse extends Response {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    static String OPENID_SESSION_TYPE = "session_type";
    static String OPENID_ASSOCIATION_TYPE = "assoc_type";

    private static String OPENID_ASSOC_NS = "ns";
    private static String OPENID_ERROR_CODE = "error_code";
    private static String OPENID_ASSOCIATION_HANDLE = "assoc_handle";
    private static String OPENID_MAC_KEY = "mac_key";

    static String OPENID_ENC_MAC_KEY = "enc_mac_key";
    private static String OPENID_DH_SERVER_PUBLIC = "dh_server_public";
    private static String OPENID_EXPIRES_IN = "expires_in";
    private String sessionType;
    private String associationType;
    private String associationHandle;
    private int expiresIn;
    private byte[] macKey;
    private BigInteger dhServerPublic;
    private byte[] encryptedMacKey;
    private String errorCode;

    public String getErrorCode() {
        return this.errorCode;
    }

    public String getAssociationHandle() {
        return this.associationHandle;
    }

    public BigInteger getDhServerPublic() {
        return this.dhServerPublic;
    }

    public byte[] getMacKey() {
        return this.macKey;
    }

    public byte[] getEncryptedMacKey() {
        return this.encryptedMacKey;
    }

    public int getExpiresIn() {
        return this.expiresIn;
    }

    public String getAssociationType() {
        return this.associationType;
    }

    public String getSessionType() {
        return this.sessionType;
    }

    Map toMap() {
        Map map = super.toMap();

        String ns = (String) map.get(Message.OPENID_NS);
        if (ns != null) {
            map.put(OPENID_ASSOC_NS, ns);
            map.remove(Message.OPENID_NS);
        }

        if (this.errorCode != null) {
            map.put(OPENID_ERROR_CODE, this.errorCode);
        } else {
            if ( ( isVersion2() )
                    || ( !AssociationRequest.NO_ENCRYPTION.equals(this.sessionType) ) ) {
                map.put(OPENID_SESSION_TYPE, this.sessionType);
            }
            map.put(OPENID_ASSOCIATION_HANDLE, this.associationHandle);
            map.put(OPENID_ASSOCIATION_TYPE, this.associationType);
            map.put(OPENID_EXPIRES_IN, "" + this.expiresIn);
            if (this.macKey != null) {
                map.put(OPENID_MAC_KEY, Crypto.convertToString(this.macKey));
            } else if (this.encryptedMacKey != null) {
                map.put(OPENID_DH_SERVER_PUBLIC, Crypto.convertToString(this.dhServerPublic));
                map.put(OPENID_ENC_MAC_KEY, Crypto.convertToString(this.encryptedMacKey));
            }
        }
        return map;
    }

    AssociationResponse(AssociationRequest ar, Association a, Crypto crypto) {
        super(null);
        this.ns = ar.getNamespace();
        if (a.isSuccessful()) {
            this.sessionType = a.getSessionType();
            this.associationHandle = a.getHandle();
            this.associationType = a.getAssociationType();
            this.expiresIn = a.getLifetime().intValue();
            this.dhServerPublic = a.getPublicDhKey();
            if ( a.isEncrypted() )
                this.encryptedMacKey = a.getEncryptedMacKey();
            else
                this.macKey = a.getMacKey();
        } else {
            this.errorCode = a.getErrorCode();
            this.error = a.getError();
        }
    }

    AssociationResponse(Map map) throws OpenIdException {
        super(map);
        Set set = map.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if ( OPENID_SESSION_TYPE.equals(key) )
                this.sessionType = AssociationRequest.parseSessionType(value);
            else if ( OPENID_ASSOCIATION_TYPE.equals(key) ) {
                this.associationType = AssociationRequest.parseAssociationType(value);
            } else if ( OPENID_DH_SERVER_PUBLIC.equals(key) ) {
                this.dhServerPublic = Crypto.convertToBigIntegerFromString(value);
            } else if ( OPENID_ASSOCIATION_HANDLE.equals(key) ) {
                this.associationHandle = value;
            } else if ( OPENID_EXPIRES_IN.equals(key) ) {
                this.expiresIn = Integer.parseInt(value);
            } else if ( OPENID_MAC_KEY.equals(key) ) {
                this.macKey = Crypto.convertToBytes(value);
            } else if ( OPENID_ENC_MAC_KEY.equals(key) ) {
                this.encryptedMacKey = Crypto.convertToBytes(value);
            } else if ( OPENID_ERROR_CODE.equals(key) ) {
                this.errorCode = value;
            } else if ( OPENID_ASSOC_NS.equals(key) ) {
                this.ns = value;
            }
        }
    }

    public String toString() {
        String s = "[AssociationResponse " + super.toString()
                + ", session type=" + this.sessionType
                + ", association type=" + this.associationType
                + ", association handle=" + this.associationHandle
                + ", expires in=" + this.expiresIn;

        if (this.dhServerPublic != null) {
            s = s + ", server public key=" + Crypto.convertToString(this.dhServerPublic);
        }

        if (this.macKey != null) {
            s = s + ", MAC key=" + Crypto.convertToString(this.macKey);
        }
        if (this.encryptedMacKey != null) {
            s = s + ", encrypted MAC key=" + Crypto.convertToString(this.encryptedMacKey);
        }

        if (this.errorCode != null) {
            s = s + ", error code=" + this.errorCode;
        }
        s = s + "]";

        return s;
    }
}