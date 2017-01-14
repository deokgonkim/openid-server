package net.dgkim.openid.util;

import javax.servlet.http.HttpServletRequest;

public class UrlUtils {
    public static String getFullUrl(HttpServletRequest request) {
        StringBuffer b = getServletUrl(request);
        String queryString = request.getQueryString();
        if (queryString != null) {
            b.append("?").append(queryString);
        }

        return b.toString();
    }

    public static StringBuffer getServletUrl(HttpServletRequest request) {
        StringBuffer b = new StringBuffer(getBaseUrl(request));
        String servletPath = request.getServletPath();
        if (servletPath != null) {
            b.append(servletPath);
        }

        return b;
    }

    public static String getBaseUrl(HttpServletRequest request) {
        StringBuffer b = new StringBuffer();
        b.append(getHostUrl(request));
        String context = request.getContextPath();
        if (context != null) {
            b.append(context);
        }

        return b.toString();
    }

    public static String getHostUrl(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        String port = ":" + request.getServerPort();

        String start = scheme + "://" + serverName + port;

        return start;
    }
}