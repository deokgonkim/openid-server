package net.dgkim.openid;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Logger;

public class AuthenticationRequest extends Request {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private Map extendedMap;
    private String claimed_id;
    private String identity;
    private String handle;
    private String returnTo;
    private String trustRoot;
    private SimpleRegistration sreg;
    public static final String OPENID_CLAIMED_ID = "openid.claimed_id";
    public static final String OPENID_IDENTITY = "openid.identity";
    public static final String OPENID_ASSOC_HANDLE = "openid.assoc_handle";
    public static final String ID_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";
    public static final String CHECKID_IMMEDIATE = "checkid_immediate";
    public static final String CHECKID_SETUP = "checkid_setup";
    public static final String OPENID_RETURN_TO = "openid.return_to";
    public static final String OPENID_TRUST_ROOT = "openid.trust_root";
    public static final String OPENID_REALM = "openid.realm";
    public static String OPENID_DH_CONSUMER_PUBLIC = "openid.dh_consumer_public";

    public static String OPENID_SESSION_TYPE = "openid.session_type";
    public static final String DH_SHA1 = "DH-SHA1";
    private static Map statelessMap = new HashMap();
    private static AssociationRequest statelessAr;

    static {
        statelessMap.put(OPENID_SESSION_TYPE, "DH-SHA1");
        statelessMap.put(OPENID_DH_CONSUMER_PUBLIC, Crypto.convertToString(BigInteger.valueOf(1L)));
        try {
            statelessAr = new AssociationRequest(statelessMap, "");
        } catch (OpenIdException e) {
            throw new RuntimeException(e);
        }
    }

    public static AuthenticationRequest create(String identity,
                                                String returnTo,
                                                String trustRoot,
                                                String assocHandle)
                                                        throws OpenIdException {
        Map map = new HashMap();
        map.put("openid.mode", "checkid_setup");
        map.put("openid.identity", identity);
        map.put("openid.claimed_id", identity);
        map.put("openid.return_to", returnTo);
        map.put("openid.trust_root", trustRoot);
        map.put("openid.realm", trustRoot);
        map.put(Message.OPENID_NS, Message.OPENID_20_NAMESPACE);
        map.put("openid.assoc_handle", assocHandle);
        return new AuthenticationRequest(map, "checkid_setup");
    }

    AuthenticationRequest(Map map, String mode) throws OpenIdException {
        super(map, mode);
        Set set = map.entrySet();
        this.extendedMap = new HashMap();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if (Message.OPENID_NS.equals(key)) {
                this.ns = value;
            } else if ("openid.identity".equals(key)) {
                this.identity = value;
            } else if ("openid.claimed_id".equals(key)) {
                this.claimed_id = value;
            } else if ("openid.assoc_handle".equals(key)) {
                this.handle = value;
            } else if ("openid.return_to".equals(key)) {
                this.returnTo = value;
            } else if ( ("openid.trust_root".equals(key)) || ("openid.realm".equals(key)) ) {
                this.trustRoot = value;
            } else {
                if ((key == null)
                        || ((!(key.startsWith("openid."))) && (!(key.startsWith("openid1"))))) {
                    continue;
                }
                String foo = key;
                if ((Message.OPENID_RESERVED_WORDS.contains(foo.substring(7)))
                        || (foo.startsWith("openid.sreg."))) {
                    continue;
                }
                this.extendedMap.put(foo, value);
            }
        }

        this.sreg = new SimpleRegistration(map);

        checkInvariants();
    }

    Map toMap() {
        Map map = super.toMap();

        if (this.claimed_id != null) {
            map.put("openid.claimed_id", this.claimed_id);
        }
        map.put("openid.identity", this.identity);
        map.put("openid.assoc_handle", this.handle);
        map.put("openid.return_to", this.returnTo);
        map.put("openid.trust_root", this.trustRoot);
        map.put("openid.realm", this.trustRoot);

        if ((this.extendedMap != null) && (!(this.extendedMap.isEmpty()))) {
            Iterator iter = this.extendedMap.entrySet().iterator();
            while (iter.hasNext()) {
                Map.Entry mapEntry = (Map.Entry) iter.next();
                String key = (String) mapEntry.getKey();
                String value = (String) mapEntry.getValue();
                if (value == null) {
                    continue;
                }

                map.put("openid." + key, value);
            }

        }

        return map;
    }

    public boolean isImmediate() {
        return "checkid_immediate".equals(this.mode);
    }

    private void checkInvariants() throws OpenIdException {
        if (this.mode == null) {
            throw new OpenIdException("Missing mode");
        }
        if (this.identity == null) {
            throw new OpenIdException("Missing identity");
        }
        if ((this.claimed_id != null) && (!(isVersion2()))) {
            throw new OpenIdException("claimed_id not valid in version 1.x");
        }
        if (this.trustRoot == null) {
            if (this.returnTo != null) {
                this.trustRoot = this.returnTo;
            } else {
                throw new OpenIdException("Missing trust root");
            }
        }

        checkTrustRoot();

        Set namespaces = new HashSet();
        Set entries = new HashSet();
        Set set = this.extendedMap.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();

            if (key.startsWith("ns.")) {
                key = key.substring(3);
                if (Message.OPENID_RESERVED_WORDS.contains(key)) {
                    throw new OpenIdException("Cannot redefine: " + key);
                }
                if (namespaces.contains(key)) {
                    throw new OpenIdException("Multiple definitions: " + key);
                }
                namespaces.add(key);
            } else {
                if (entries.contains(key)) {
                    throw new OpenIdException("Multiple definitions: " + key);
                }
                entries.add(key);
            }

        }

        if (isVersion2())
            for (Iterator iter = entries.iterator(); iter.hasNext();) {
                String key = (String) iter.next();
                int period = key.indexOf(46);
                if (period != -1) {
                    key = key.substring(0, period);
                }
                if (!(namespaces.contains(key)))
                    throw new OpenIdException("No such namespace: " + key);
            }
    }

    private void checkTrustRoot() throws OpenIdException {
        URL r;
        URL t;
        if (this.trustRoot == null) {
            throw new OpenIdException("No openid.trust_root given");
        }

        if (this.trustRoot.indexOf(35) > 0) {
            throw new OpenIdException("URI fragments are not allowed");
        }

        try {
            r = new URL(this.returnTo);
            t = new URL(this.trustRoot);
        } catch (MalformedURLException e) {
            throw new OpenIdException("Malformed URL");
        }

        String tHost = new StringBuffer(t.getHost()).reverse().toString();
        String rHost = new StringBuffer(r.getHost()).reverse().toString();

        String[] tNames = tHost.split("\\.");
        String[] rNames = rHost.split("\\.");
        int len = (tNames.length > rNames.length) ? rNames.length
                : tNames.length;

        for (int i = 0; i < len; i += 1) {
            if ((tNames[i].equals(rNames[i])) || (tNames[i].equals("*")))
                continue;
            throw new OpenIdException("returnTo not in trustroot set: "
                    + tNames[i] + ", " + rNames[i]);
        }

//        if ((i < tNames.length) && (!(tNames[i].equals("*")))) {
//            throw new OpenIdException("returnTo not in trustroot set: "
//                    + tNames[1]);
//        }

        String tPath = t.getPath();
        String rPath = r.getPath();

        int n = rPath.indexOf(tPath);
        if (n != 0)
            throw new OpenIdException("return to & trust root paths mismatch");
    }

    public Response processUsing(ServerInfo si) throws OpenIdException {
        Store store = si.getStore();
        Crypto crypto = si.getCrypto();
        Association assoc = null;
        String invalidate = null;
        if (this.handle != null) {
            assoc = store.findAssociation(this.handle);
            if ((assoc != null) && (assoc.hasExpired())) {
                log.info("Association handle has expired: " + this.handle);
                assoc = null;
            }
        }
        if ((this.handle == null) || (assoc == null)) {
            log.info("Invalidating association handle: " + this.handle);
            invalidate = this.handle;
            assoc = store.generateAssociation(statelessAr, crypto);
            store.saveAssociation(assoc);
        }

        return new AuthenticationResponse(si, this, assoc, crypto, invalidate);
    }

    public String getIdentity() {
        return this.identity;
    }

    public Map getExtensions() {
        return this.extendedMap;
    }

    public void addExtensions(Map map) {
        Iterator it = map.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry mapEntry = (Map.Entry) it.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            this.extendedMap.put(key, value);
        }
    }

    public void addExtension(Extension ext) {
        addExtensions(ext.getParamMap());
    }

    public boolean isIdentifierSelect() {
        return "http://specs.openid.net/auth/2.0/identifier_select"
                .equals(this.identity);
    }

    public String getClaimedIdentity() {
        return this.claimed_id;
    }

    public void setIdentity(String identity) {
        this.identity = identity;
    }

    public String getReturnTo() {
        return this.returnTo;
    }

    public String getHandle() {
        return this.handle;
    }

    public String getTrustRoot() {
        return this.trustRoot;
    }

    public SimpleRegistration getSimpleRegistration() {
        return this.sreg;
    }

    public void setSimpleRegistration(SimpleRegistration sreg) {
        this.sreg = sreg;
    }

    public String toString() {
        return "[AuthenticationRequest " + super.toString()
                + ", sreg=" + this.sreg
                + ", claimed identity=" + this.claimed_id
                + ", identity=" + this.identity
                + ", handle=" + this.handle
                + ", return to=" + this.returnTo
                + ", trust root=" + this.trustRoot + "]";
    }
}