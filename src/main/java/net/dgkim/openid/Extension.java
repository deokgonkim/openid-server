package net.dgkim.openid;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TimeZone;

public class Extension {
    private static String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    protected String ns;
    protected String prefix;
    protected Map params;

    public Extension(String ns, String prefix) {
        this.ns = ns;
        this.prefix = prefix;
        this.params = null;
    }

    public Extension(String ns, Map extensionMap) {
        this.ns = ns;
        getParams(extensionMap);
    }

    public void getParams(Map extensionMap) {
        this.params = null;
        String prefix = getPrefix(extensionMap);
        if (prefix == null) {
            return;
        }
        this.prefix = prefix;
        this.params = new HashMap();
        Iterator it = extensionMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry mapEntry = (Map.Entry) it.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            if (key.startsWith(prefix)) {
                this.params.put(key.substring(prefix.length() + 1), value);
            }
        }
        if (this.params.isEmpty())
            this.params = null;
    }

    public boolean isValid() {
        return (this.params != null);
    }

    public boolean isValid(Map extensionMap) {
        return (getPrefix(extensionMap) != null);
    }

    public String getPrefix(Map extensionMap) {
        Iterator it = extensionMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry mapEntry = (Map.Entry) it.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            if ((key.startsWith("ns.")) && (value.equals(this.ns))) {
                return key.substring(3);
            }
        }

        return null;
    }

    public void clearParam(String name) {
        if (this.params != null)
            this.params.remove(name);
    }

    public String getParam(String name) {
        return ((String) this.params.get(name));
    }

    public void setParam(String name, String value) {
        if (this.params == null) {
            this.params = new HashMap();
        }
        this.params.put(name, value);
    }

    public Integer getIntParam(String name) throws OpenIdException {
        try {
            String paramStr = getParam(name);
            if (paramStr != null) {
                return new Integer(paramStr);
            }

            return null;
        } catch (NumberFormatException e) {
            throw new OpenIdException("Invalid " + name + " parameter", e);
        }
    }

    public void setIntParam(String name, Integer value) {
        setParam(name, (value == null) ? null : value.toString());
    }

    public Date getDateParam(String name) throws OpenIdException {
        SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        try {
            String paramStr = getParam(name);
            if (paramStr != null) {
                return dateFormat.parse(paramStr.toUpperCase());
            }

            return null;
        } catch (ParseException e) {
            throw new OpenIdException("Invalid " + name + " parameter", e);
        }
    }

    public void setDateParam(String name, Date value) {
        SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        setParam(name, dateFormat.format(value));
    }

    public List getListParam(String name, String separator) {
        List paramList = new ArrayList();
        String paramStr = getParam(name);
        if (paramStr != null) {
            String[] paramArray = paramStr.split(separator);
            for (int i = 0; i < paramArray.length; ++i) {
                paramList.add(paramArray[i]);
            }
        }

        return paramList;
    }

    public Set getSetParam(String name, String separator) {
        return new LinkedHashSet(getListParam(name, separator));
    }

    public void setListParam(String name, Collection paramList, String separator) {
        StringBuffer paramStr = new StringBuffer("");
        Iterator it = paramList.iterator();
        while (it.hasNext()) {
            String param = (String) it.next();
            paramStr.append(param);
            if (it.hasNext()) {
                paramStr.append(separator);
            }
        }
        setParam(name, paramStr.toString());
    }

    public Map getParamMap(String nsSuffix) {
        if ((nsSuffix == null) || (nsSuffix.length() == 0)) {
            throw new IllegalArgumentException("Missing namespace alias for "
                    + this.ns);
        }

        Map map = new HashMap();

        Iterator it = this.params.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry mapEntry = (Map.Entry) it.next();
            String key = (String) mapEntry.getKey();
            String value = (String) mapEntry.getValue();
            if (value != null) {
                map.put(nsSuffix + "." + key, value);
            }
        }
        map.put("ns." + nsSuffix, this.ns);

        return map;
    }

    public Map getParamMap() {
        return getParamMap(this.prefix);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer("");
        sb.append("[Extension ").append(this.ns).append(", ");
        sb.append("prefix=").append(this.prefix).append(", ");
        if (this.params == null) {
            sb.append("No extension params");
        } else {
            Iterator it = this.params.keySet().iterator();
            while (it.hasNext()) {
                String key = (String) it.next();
                sb.append(key).append("='")
                        .append((String) this.params.get(key)).append("'");
                if (it.hasNext()) {
                    sb.append(", ");
                }
            }
        }
        sb.append("]");

        return sb.toString();
    }
}