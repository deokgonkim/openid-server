package net.dgkim.openid;

import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Logger;

public class AuthenticationResponse extends Response {
    private static Logger log = Logger.getLogger("net.dgkim.openid");

    public static String OPENID_PREFIX = "openid.";
    public static String OPENID_RETURN_TO = "openid.return_to";
    public static String OPENID_OP_ENDPOINT = "openid.op_endpoint";
    public static String OPENID_IDENTITY = "openid.identity";
    public static String OPENID_ERROR = "openid.error";
    public static String OPENID_NONCE = "openid.response_nonce";
    public static String OPENID_INVALIDATE_HANDLE = "openid.invalidate_handle";
    public static String OPENID_ASSOCIATION_HANDLE = "openid.assoc_handle";
    public static String OPENID_SIGNED = "openid.signed";

    public static String OPENID_SIG = "openid.sig";
    private Map extendedMap;
    private String claimed_id;
    private String identity;
    private String returnTo;
    private String nonce;
    private String invalidateHandle;
    private String associationHandle;
    private String signed;
    private String algo;
    private String signature;
    private SimpleRegistration sreg;
    private String urlEndPoint;
    private byte[] key;

    public String getSignature() {
        return this.signature;
    }

    public String getSignedList() {
        return this.signed;
    }

    public String getAssociationHandle() {
        return this.associationHandle;
    }

    public Map toMap() {
        Map map = super.toMap();

        if (isVersion2()) {
            map.put(OPENID_OP_ENDPOINT, this.urlEndPoint);
        }
        map.put(OPENID_MODE, this.mode);
        map.put(OPENID_IDENTITY, this.identity);
        map.put(OPENID_RETURN_TO, this.returnTo);
        map.put(OPENID_NONCE, this.nonce);

        map.put("rp_nonce", this.nonce);
        if (this.claimed_id != null) {
            map.put("openid.claimed_id", this.claimed_id);
        }
        if (this.invalidateHandle != null) {
            map.put(OPENID_INVALIDATE_HANDLE, this.invalidateHandle);
        }

        map.put(OPENID_ASSOCIATION_HANDLE, this.associationHandle);

        if (this.signed != null) {
            map.put(OPENID_SIGNED, this.signed);
        }
        map.put(OPENID_SIG, this.signature);

        Map sregMap = this.sreg.getSuppliedValues();

        log.warning("sreg in authnresp = " + this.sreg);
        Set set = sregMap.entrySet();

        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            map.put("openid.sreg." + key, value);
        }
        if ((!(set.isEmpty())) && (isVersion2())) {
            map.put(Message.OPENID_NS + ".sreg", this.sreg.getNamespace());
        }

        if ((this.extendedMap != null) && (!(this.extendedMap.isEmpty()))) {
            set = this.extendedMap.entrySet();
            for (Iterator iter = set.iterator(); iter.hasNext();) {
                Map.Entry mapEntry = (Map.Entry) iter.next();
                String key = (String) mapEntry.getKey();
                String value = (String) mapEntry.getValue();

                map.put(key, value);
            }
        }
        System.out.println(" resposne ext : " + this.extendedMap);

        return map;
    }

    private String generateNonce() {
        String crumb = Crypto.generateCrumb();
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss'Z'");

        return df.format(new Date(System.currentTimeMillis() - 32400000L))
                + crumb;
    }

    public static String toUrlStringResponse(Request req, OpenIdException e) {
        String str2;
        Map map = new HashMap();
        map.put(OPENID_MODE, "error");
        if (req != null) {
            if (req.isVersion2()) {
                map.put(OPENID_NS, req.getNamespace());
            }
            map.put(OPENID_ERROR, e.getMessage());
        } else {
            map.put(OPENID_ERROR, "OpenID request error");
        }

        try {
            return new AuthenticationResponse(map).toUrlString();
        } catch (OpenIdException ex) {
            log.severe(ex.getMessage());
            str2 = "internal error";
        }
        return str2;
    }

    public String sign(byte[] key, String signed) throws OpenIdException {
        return sign(this.algo, key, signed);
    }

    public String sign(String algorithm, byte[] key, String signed)
            throws OpenIdException {
        Map map = toMap();
        log.fine("in sign() map=" + map);
        log.fine("in sign() signed=" + signed);
        StringTokenizer st = new StringTokenizer(signed, ",");
        StringBuffer sb = new StringBuffer();
        while (st.hasMoreTokens()) {
            String s = st.nextToken();
            String name = "openid." + s;
            String value = (String) map.get(name);
            if (value == null) {
                throw new OpenIdException("Cannot sign non-existent mapping: "
                        + s);
            }

            sb.append(s);
            sb.append(':');
            sb.append(value);
            sb.append('\n');
        }
        try {
            byte[] b;
            if (algorithm == null) {
                algorithm = AssociationRequest.HMAC_SHA1;
            }
            if (algorithm.equals(AssociationRequest.HMAC_SHA1))
                b = Crypto.hmacSha1(key, sb.toString().getBytes("UTF-8"));
            else if (algorithm.equals(AssociationRequest.HMAC_SHA256))
                b = Crypto.hmacSha256(key, sb.toString().getBytes("UTF-8"));
            else {
                throw new OpenIdException("Unknown signature algorithm");
            }

            return Crypto.convertToString(b);
        } catch (UnsupportedEncodingException e) {
            throw new OpenIdException(e);
        } catch (InvalidKeyException e) {
            throw new OpenIdException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new OpenIdException(e);
        }
    }

    AuthenticationResponse(ServerInfo serverInfo, AuthenticationRequest ar,
            Association a, Crypto crypto, String invalidateHandle)
            throws OpenIdException {
        super(null);
        this.mode = "id_res";
        this.claimed_id = ar.getClaimedIdentity();
        this.identity = ar.getIdentity();
        this.returnTo = ar.getReturnTo();
        this.ns = ar.getNamespace();
        this.nonce = generateNonce();
        this.urlEndPoint = serverInfo.getUrlEndPoint();
        this.invalidateHandle = invalidateHandle;
        this.associationHandle = a.getHandle();
        this.signed = "assoc_handle,identity,response_nonce,return_to";
        if (this.mode != null) {
            this.signed += ",mode";
        }
        if (this.claimed_id != null) {
            this.signed += ",claimed_id";
        }
        if (isVersion2()) {
            this.signed += ",op_endpoint";
        }
        this.sreg = ar.getSimpleRegistration();
        log.fine("sreg=" + this.sreg);
        if (this.sreg != null) {
            Map map = this.sreg.getSuppliedValues();
            log.fine("sreg supplied values=" + map);
            Set set = map.entrySet();
            for (Iterator iter = set.iterator(); iter.hasNext();) {
                Map.Entry mapEntry = (Map.Entry) iter.next();
                String key = (String) mapEntry.getKey();
                AuthenticationResponse tmp318_317 = this;
                tmp318_317.signed = tmp318_317.signed + ",sreg." + key;
            }
        }
        this.key = a.getMacKey();
        this.algo = a.getAssociationType();
        this.signature = sign(this.key, this.signed);

        this.extendedMap = ar.getExtensions();
        System.out.println(" resp oooo " + this.extendedMap);
    }

    public AuthenticationResponse(Map map) throws OpenIdException {
        super(map);
        Set set = map.entrySet();
        this.extendedMap = new HashMap();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if (OPENID_MODE.equals(key)) {
                this.mode = value;
            } else if (OPENID_IDENTITY.equals(key)) {
                this.identity = value;
            } else if ("openid.claimed_id".equals(key)) {
                this.claimed_id = value;
            } else if (OPENID_RETURN_TO.equals(key)) {
                this.returnTo = value;
            } else if (OPENID_NONCE.equals(key)) {
                this.nonce = value;
            } else if (OPENID_INVALIDATE_HANDLE.equals(key)) {
                this.invalidateHandle = value;
            } else if (OPENID_ASSOCIATION_HANDLE.equals(key)) {
                this.associationHandle = value;
            } else if (OPENID_SIGNED.equals(key)) {
                this.signed = value;
            } else if (OPENID_SIG.equals(key)) {
                this.signature = value;
            } else if (OPENID_OP_ENDPOINT.equals(key)) {
                this.urlEndPoint = value;

                if (this.ns == null)
                    this.ns = Message.OPENID_20_NAMESPACE;
            } else {
                if ((key == null)
                        || ((!(key.startsWith("openid."))) && (!(key
                                .startsWith("openid1")))))
                    continue;
                String foo = key;
                if ((Message.OPENID_RESERVED_WORDS.contains(foo.substring(7)))
                        || (foo.startsWith("openid.sreg.")))
                    continue;
                this.extendedMap.put(foo, value);
            }
        }

        this.sreg = SimpleRegistration.parseFromResponse(map);
        log.fine("authn resp constr sreg=" + this.sreg);
    }

    public Map getExtensions() {
        return this.extendedMap;
    }

    public void addExtensions(Map map) throws OpenIdException {
        Iterator it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry mapEntry = (Map.Entry) it.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            this.extendedMap.put(key, value);
            AuthenticationResponse tmp69_68 = this;
            tmp69_68.signed = tmp69_68.signed + "," + key;
        }

        this.signature = sign(this.key, this.signed);
    }

    public void addExtension(Extension ext) throws OpenIdException {
        addExtensions(ext.getParamMap());
    }

    public String toString() {
        String s = "[AuthenticationResponse " + super.toString();
        if (this.sreg != null) {
            s = s + ", sreg=" + this.sreg;
        }
        s = s + ", mode=" + this.mode
              + ", algo=" + this.algo
              + ", nonce=" + this.nonce
              + ", association handle=" + this.associationHandle
              + ", invalidation handle=" + this.invalidateHandle
              + ", signed=" + this.signed
              + ", signature=" + this.signature
              + ", identity=" + this.identity
              + ", return to=" + this.returnTo + "]";

        return s;
    }

    public String getClaimedId() {
        return this.claimed_id;
    }

    public String getIdentity() {
        return this.identity;
    }

    public String getReturnTo() {
        return this.returnTo;
    }

    public String getNonce() {
        return this.nonce;
    }

    public String getInvalidateHandle() {
        return this.invalidateHandle;
    }

    public String getSigned() {
        return this.signed;
    }

    public String getAlgo() {
        return this.algo;
    }

    public SimpleRegistration getSreg() {
        return this.sreg;
    }

    public String getUrlEndPoint() {
        return this.urlEndPoint;
    }
}