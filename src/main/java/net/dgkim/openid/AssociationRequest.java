package net.dgkim.openid;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

public class AssociationRequest extends Request {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    private String sessionType;
    private String associationType;
    private BigInteger dhModulus;
    private BigInteger dhGenerator;
    private BigInteger dhConsumerPublic;
    private static String OPENID_SESSION_TYPE = "openid.session_type";
    private static String OPENID_ASSOCIATION_TYPE = "openid.assoc_type";
    private static String OPENID_DH_MODULUS = "openid.dh_modulus";
    private static String OPENID_DH_GENERATOR = "openid.dh_gen";
    private static String OPENID_DH_CONSUMER_PUBLIC = "openid.dh_consumer_public";

    public static String NO_ENCRYPTION = "no-encryption";

    public static String DH_SHA1 = "DH-SHA1";

    public static String DH_SHA256 = "DH-SHA256";

    public static String HMAC_SHA1 = "HMAC-SHA1";

    public static String HMAC_SHA256 = "HMAC-SHA256";

    static String parseSessionType(String s) {
        if (NO_ENCRYPTION.equals(s)) {
            return NO_ENCRYPTION;
        }
        if (DH_SHA1.equals(s)) {
            return DH_SHA1;
        }
        if (DH_SHA256.equals(s)) {
            return DH_SHA256;
        }
        throw new IllegalArgumentException("Cannot parse session type: " + s);
    }

    Map toMap() {
        Map map = super.toMap();
        map.put(OPENID_SESSION_TYPE, this.sessionType);
        map.put(OPENID_ASSOCIATION_TYPE, this.associationType);
        map.put(OPENID_DH_CONSUMER_PUBLIC, Crypto.convertToString(this.dhConsumerPublic));
        return map;
    }

    static String parseAssociationType(String s) {
        if (HMAC_SHA1.equals(s)) {
            return HMAC_SHA1;
        }
        if (HMAC_SHA256.equals(s)) {
            return HMAC_SHA256;
        }
        throw new IllegalArgumentException("Cannot parse association type: " + s);
    }

    private static BigInteger parseDhModulus(String s) {
        return Crypto.convertToBigIntegerFromString(s);
    }

    private static BigInteger parseDhGenerator(String s) {
        return Crypto.convertToBigIntegerFromString(s);
    }

    private static BigInteger parseDhConsumerPublic(String s) {
        return Crypto.convertToBigIntegerFromString(s);
    }

    public static AssociationRequest create(Crypto crypto) {
        try {
            BigInteger pubKey = crypto.getPublicKey();
            Map map = new HashMap();
            map.put("openid.mode", "associate");
            map.put(OPENID_ASSOCIATION_TYPE, HMAC_SHA1);
            map.put(OPENID_SESSION_TYPE, DH_SHA1);
            map.put(Message.OPENID_NS, Message.OPENID_20_NAMESPACE);
            map.put(OPENID_DH_CONSUMER_PUBLIC, Crypto.convertToString(pubKey));
            return new AssociationRequest(map, "associate");
        } catch (OpenIdException e) {
            throw new IllegalArgumentException(e.toString());
        }
    }

    AssociationRequest(Map map, String mode) throws OpenIdException {
        super(map, mode);
        this.sessionType = NO_ENCRYPTION;
        this.associationType = HMAC_SHA1;
        this.dhModulus = DiffieHellman.DEFAULT_MODULUS;
        this.dhGenerator = DiffieHellman.DEFAULT_GENERATOR;
        Set set = map.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            if (OPENID_SESSION_TYPE.equals(key))
                this.sessionType = parseSessionType(value);
            else if (OPENID_ASSOCIATION_TYPE.equals(key)) {
                this.associationType = parseAssociationType(value);
            } else if (OPENID_DH_MODULUS.equals(key))
                this.dhModulus = parseDhModulus(value);
            else if (OPENID_DH_GENERATOR.equals(key))
                this.dhGenerator = parseDhGenerator(value);
            else if (OPENID_DH_CONSUMER_PUBLIC.equals(key)) {
                this.dhConsumerPublic = parseDhConsumerPublic(value);
            }
        }
        checkInvariants();
    }

    public boolean isNotEncrypted() {
        return NO_ENCRYPTION.equals(this.sessionType);
    }

    private void checkInvariants() throws OpenIdException {
        if (this.mode == null) {
            throw new OpenIdException("Missing mode");
        }
        if (this.associationType == null) {
            throw new OpenIdException("Missing association type");
        }
        if (this.sessionType == null) {
            throw new OpenIdException("Missing session type");
        }
        if ( ( this.sessionType.equals(DH_SHA1) && !this.associationType.equals(HMAC_SHA1) )
                || ( this.sessionType.equals(DH_SHA256) && !this.associationType.equals(HMAC_SHA256) ) ) {
            throw new OpenIdException("Mismatch " + OPENID_SESSION_TYPE + " and " + OPENID_ASSOCIATION_TYPE);
        }
        if ( ( !this.sessionType.equals(DH_SHA1) && !this.sessionType.equals(DH_SHA256) )
                || this.dhConsumerPublic != null )
            return;
        throw new OpenIdException("Missing " + OPENID_DH_CONSUMER_PUBLIC);
    }

    public Response processUsing(ServerInfo si) throws OpenIdException {
        Store store = si.getStore();
        Crypto crypto = si.getCrypto();
        Association a = store.generateAssociation(this, crypto);
        store.saveAssociation(a);
        return new AssociationResponse(this, a, crypto);
    }

    public BigInteger getDhModulus() {
        return this.dhModulus;
    }

    public BigInteger getDhGenerator() {
        return this.dhGenerator;
    }

    public BigInteger getDhConsumerPublic() {
        return this.dhConsumerPublic;
    }

    public String getSessionType() {
        return this.sessionType;
    }

    public String getAssociationType() {
        return this.associationType;
    }

    public String toString() {
        return "[AssociationRequest " + super.toString() + ", session type=" + this.sessionType + ", association type=" + this.associationType + "]";
    }
}