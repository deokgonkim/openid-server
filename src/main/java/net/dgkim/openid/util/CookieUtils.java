package net.dgkim.openid.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CookieUtils {
    private static final int DEFAULT_AGE = 2592000;

    public static void setCookie(HttpServletResponse response,
            String cookieName, String value) {
        Cookie cookie = new Cookie(cookieName, value);
        cookie.setMaxAge(2592000);
        response.addCookie(cookie);
    }

    public static String getCookieValue(HttpServletRequest request,
            String cookieName, String defaultValue) {
        Cookie cookie = getCookie(request, cookieName);
        if (cookie == null) {
            return defaultValue;
        }

        return cookie.getValue();
    }

    public static Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (int i = 0; i < cookies.length; ++i) {
            Cookie cookie = cookies[i];
            if (cookieName.equals(cookie.getName())) {
                return cookie;
            }
        }
        return null;
    }
}