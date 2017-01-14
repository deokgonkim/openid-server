package net.dgkim.openid;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Logger;

public class MessageParser {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    static char newline = '\n';

    static String toPostString(Message message) throws OpenIdException {
        return toStringDelimitedBy(message, ":", newline);
    }

    static String toUrlString(Message message) throws OpenIdException {
        return toStringDelimitedBy(message, "=", '&');
    }

    private static String toStringDelimitedBy(Message message, String kvDelim,
            char lineDelim) throws OpenIdException {
        Map map = message.toMap();
        Set set = map.entrySet();
        StringBuffer sb = new StringBuffer();
        try {
            for (Iterator iter = set.iterator(); iter.hasNext();) {
                Map.Entry mapEntry = (Map.Entry) iter.next();
                String key = (String) mapEntry.getKey();
                String value = (String) mapEntry.getValue();

                if (lineDelim == newline) {
                    sb.append(key + kvDelim + value);
                    sb.append(lineDelim);
                } else if (value != null) {
                    sb.append(URLEncoder.encode(key, "UTF-8") + kvDelim
                            + URLEncoder.encode(value, "UTF-8"));

                    if (iter.hasNext())
                        sb.append(lineDelim);
                } else {
                    throw new OpenIdException("Value for key '" + key
                            + "' is null in message map");
                }

            }

            return sb.toString();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Internal error");
        }
    }

    static int numberOfNewlines(String query) throws IOException {
        BufferedReader br = new BufferedReader(new StringReader(query));
        int n = 0;
        while (br.readLine() != null) {
            n += 1;
        }

        return n;
    }

    public static Map urlEncodedToMap(String query)
            throws UnsupportedEncodingException {
        Map map = new HashMap();
        if (query == null) {
            return map;
        }
        StringTokenizer st = new StringTokenizer(query, "?&=;", true);
        String previous = null;
        while (st.hasMoreTokens()) {
            String current = st.nextToken();
            if (("?".equals(current)) || ("&".equals(current))
                    || (";".equals(current))) {
                continue;
            }
            if ("=".equals(current)) {
                String name = URLDecoder.decode(previous, "UTF-8");
                if (st.hasMoreTokens()) {
                    String value = URLDecoder.decode(st.nextToken(), "UTF-8");
                    if (isGoodValue(value))
                        map.put(name, value);
                }
            } else {
                previous = current;
            }
        }

        return map;
    }

    private static boolean isGoodValue(String value) {
        return (("&".equals(value)) || (";".equals(value)));
    }

    static Map postedToMap(String query) throws IOException {
        Map map = new HashMap();
        if (query == null) {
            return map;
        }
        BufferedReader br = new BufferedReader(new StringReader(query));
        String s = br.readLine();
        while (s != null) {
            int index = s.indexOf(":");
            if (index != -1) {
                String name = s.substring(0, index);
                String value = s.substring(index + 1, s.length());
                if ((name != null) && (value != null)) {
                    map.put(name, value);
                }
            }
            s = br.readLine();
        }

        return map;
    }
}