package net.dgkim.openid;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Logger;

public class SimpleRegistration {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private Set required;
    private Set optional;
    private Map supplied;
    private String policyUrl;
    public static final String OPENID_SREG = "openid.sreg";
    public static final String OPENID_SREG_NSDEF = "openid.ns.sreg";
    public static final String OPENID_SREG_REQUIRED = "openid.sreg.required";
    public static final String OPENID_SREG_OPTIONAL = "openid.sreg.optional";
    public static final String OPENID_SREG_POLICY_URL = "openid.sreg.policy_url";
    public static final String OPENID_SREG_NAMESPACE_10 = "http://openid.net/sreg/1.0";
    public static final String OPENID_SREG_NAMESPACE_11 = "http://openid.net/extensions/sreg/1.1";
    private static final String SREG_NICKNAME = "nickname";
    private static final String SREG_EMAIL = "email";
    private static final String SREG_FULLNAME = "fullname";
    private static final String SREG_DOB = "dob";
    private static final String SREG_GENDER = "gender";
    private static final String SREG_POSTCODE = "postcode";
    private static final String SREG_COUNTRY = "country";
    private static final String SREG_LANGUAGE = "language";
    private static final String SREG_TIMEZONE = "timezone";
    private String namespace;
    private String nickName;
    private String email;
    private String fullName;
    private String dob;
    private String gender;
    private String postCode;
    private String country;
    private String language;
    private String timeZone;
    public static final Set allowed = new HashSet();

    static {
        allowed.add("nickname");
        allowed.add("email");
        allowed.add("fullname");
        allowed.add("dob");
        allowed.add("gender");
        allowed.add("postcode");
        allowed.add("country");
        allowed.add("language");
        allowed.add("timezone");
    }

    public SimpleRegistration(Set required, Set optional, Map supplied,
            String policyUrl) {
        this.required = required;
        this.optional = optional;
        this.supplied = supplied;
        this.policyUrl = policyUrl;
        this.namespace = "http://openid.net/extensions/sreg/1.1";
    }

    public SimpleRegistration(Set required, Set optional, Map supplied,
            String policyUrl, String namespace) {
        this.required = required;
        this.optional = optional;
        this.supplied = supplied;
        this.policyUrl = policyUrl;
        this.namespace = namespace;
    }

    SimpleRegistration(Map map) throws OpenIdException {
        this.required = new HashSet();
        this.optional = new HashSet();
        this.supplied = new HashMap();
        this.supplied.put("email", "dgkim@dgkim.net");
        this.supplied.put("nickname", "deoggonkim");
        this.namespace = "http://openid.net/extensions/sreg/1.1";

        Set set = map.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if ("openid.sreg.required".equals(key)) {
                addToSetFromList(this.required, value);
            } else if ("openid.sreg.optional".equals(key)) {
                addToSetFromList(this.optional, value);
            } else if ("openid.sreg.policy_url".equals(key)) {
                this.policyUrl = value;
            } else {
                if ((!("openid.ns.sreg".equals(key)))
                        || ((!("http://openid.net/sreg/1.0".equals(value))) && (!("http://openid.net/extensions/sreg/1.1"
                                .equals(value)))))
                    continue;
                this.namespace = value;
            }
        }
    }

    public boolean isRequested() {
        return this.required.isEmpty() && this.optional.isEmpty() ? false : true;
    }

    public static SimpleRegistration parseFromResponse(Map map) {
        Set req = new HashSet();
        Set opt = new HashSet();
        Map sup = new HashMap();
        String ns = "http://openid.net/extensions/sreg/1.1";

        String trigger = "openid.sreg.";
        int triggerLength = trigger.length();
        Set set = map.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();

            if (key.startsWith(trigger)) {
                sup.put(key.substring(triggerLength), value);
            } else {
                if ((!("openid.ns.sreg".equals(key)))
                        || ((!("http://openid.net/sreg/1.0".equals(value))) && (!("http://openid.net/extensions/sreg/1.1"
                                .equals(value)))))
                    continue;
                ns = value;
            }

        }

        return new SimpleRegistration(req, opt, sup, "", ns);
    }

    private void addToSetFromList(Set set, String value) {
        StringTokenizer st = new StringTokenizer(value, ",");
        while (st.hasMoreTokens()) {
            String token = st.nextToken().trim();
            if (allowed.contains(token))
                set.add(token);
            else
                log.info("Illegal sreg value: " + token);
        }
    }

    public String getPolicyUrl() {
        return this.policyUrl;
    }

    public Set getRequired() {
        return this.required;
    }

    public Set getOptional() {
        return this.optional;
    }

    public void setRequired(Set set) {
        this.required = set;
    }

    public void setOptional(Set set) {
        this.optional = set;
    }

    public String getNamespace() {
        return this.namespace;
    }

    public Map getSuppliedValues() {
        Map map = new HashMap();
        addAllNonEmpty(this.supplied, map);

        return map;
    }

    private void addAllNonEmpty(Map from, Map to) {
        Set set = from.entrySet();
        for (Iterator iter = set.iterator(); iter.hasNext();) {
            Map.Entry mapEntry = (Map.Entry) iter.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            if (value != null)
                to.put(key, value);
        }
    }

    public String toString() {
        return "[SimpleRegistration required=" + this.required + ", optional="
                + this.optional + ", supplied=" + this.supplied
                + ", policy url=" + this.policyUrl + ", namespace="
                + this.namespace + "]";
    }
}