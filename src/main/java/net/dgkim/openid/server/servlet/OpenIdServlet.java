package net.dgkim.openid.server.servlet;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import net.dgkim.openid.AuthenticationRequest;
import net.dgkim.openid.Crypto;
import net.dgkim.openid.OpenId;
import net.dgkim.openid.OpenIdException;
import net.dgkim.openid.RequestFactory;
import net.dgkim.openid.ServerInfo;
import net.dgkim.openid.Store;
import net.dgkim.openid.StoreFactory;
import net.dgkim.openid.server.MemoryStore;
import net.dgkim.openid.server.UserManager;
import net.dgkim.openid.util.CookieUtils;
import net.dgkim.openid.util.DependencyUtils;

public class OpenIdServlet extends HttpServlet {
    private static Logger log = Logger.getLogger("net.dgkim.openid");
    private static final long serialVersionUID = 297366254782L;
    private static OpenId openId;
    private Store store;
    private Crypto crypto;
    private String loginPage;
    public static final String USERNAME_ATTRIBUTE = "username";
    public static final String ID_CLAIMED = "idClaimed";
    public static final String QUERY = "query";
    public static final String COOKIE_AUTH_NAME = "authKey";
    public static final String COOKIE_USERNAME = "username";
    private static UserManager userManager;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String storeClassName = config.getInitParameter("storeClassName");
        String userManagerClassName = config
                .getInitParameter("userManagerClassName");

        this.store = StoreFactory.getInstance(storeClassName);
        MemoryStore mStore = (MemoryStore) this.store;
        mStore.setAssociationLifetime(600L);
        userManager = (UserManager) DependencyUtils
                .newInstance(userManagerClassName);

        this.crypto = new Crypto();
        this.loginPage = config.getInitParameter("loginPage");
        String endPointUrl = config.getInitParameter("endPointUrl");
        openId = new OpenId(
                new ServerInfo(endPointUrl, this.store, this.crypto));
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doQuery(request.getQueryString(), request, response);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        StringBuffer sb = new StringBuffer();
        Enumeration e = request.getParameterNames();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            String[] values = request.getParameterValues(name);
            if (values.length == 0) {
                throw new IOException("Empty value not allowed: " + name
                        + " has no value");
            }
            try {
                sb.append(URLEncoder.encode(name, "UTF-8") + "="
                        + URLEncoder.encode(values[0], "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                throw new IOException(ex.toString());
            }
            if (e.hasMoreElements()) {
                sb.append("&");
            }
        }
        doQuery(sb.toString(), request, response);
    }

    public void doQuery(String query, HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        log("\nrequest\n-------\n" + query + "\n");
        if (!(openId.canHandle(query))) {
            returnError(query, response);

            return;
        }
        try {
            boolean isAuth = openId.isAuthenticationRequest(query);
            HttpSession session = request.getSession(true);
            String user = getLoggedIn(request);
            log.fine("[OpenIdServlet] Logged in as: " + user);

            if (request.getParameter("openid.trust_root") != null) {
                session.setAttribute("openid.trust_root",
                        request.getParameter("openid.trust_root"));
            }

            if (request.getParameter("openid.return_to") != null) {
                session.setAttribute("openid.return_to",
                        request.getParameter("openid.return_to"));
            }

            if ((isAuth) && (user == null)) {
                RequestDispatcher rd = request
                        .getRequestDispatcher(this.loginPage);
                request.setAttribute("query", query);
                request.setAttribute("openid.realm",
                        request.getParameter("openid.realm"));

                session.setAttribute("query", query);

                if (request.getParameter("openid.claimed_id") == null) {
                    session.setAttribute("openid.claimed_id",
                            request.getParameter("openid.identity"));
                } else {
                    session.setAttribute("openid.claimed_id",
                            request.getParameter("openid.claimed_id"));
                }

                session.setAttribute("openid.realm",
                        request.getParameter("openid.realm"));

                response.sendRedirect(this.loginPage);

                return;
            }
            String s = openId.handleRequest(query);
            log("\nresponse\n--------\n" + s + "\n");
            if (isAuth) {
                String identity;
                AuthenticationRequest authReq = (AuthenticationRequest) RequestFactory
                        .parse(query);

                if (request.getParameter("openid.claimed_id") == null) {
                    identity = request.getParameter("openid.identity");
                } else {
                    identity = authReq.getClaimedIdentity();
                }
                if (getUserManager().canClaim(user, identity)) {
                    String returnTo = (String) session
                            .getAttribute("openid.return_to");

                    String delim = (returnTo.indexOf(63) >= 0) ? "&" : "?";
                    s = response.encodeRedirectURL(returnTo + delim + s);
                    log.fine("sending redirect to: " + s);
                    response.sendRedirect(s);
                } else {
                    throw new OpenIdException("User cannot claim this id.");
                }
            } else {
                int len = s.length();
                PrintWriter out = response.getWriter();
                response.setHeader("Content-Length", Integer.toString(len));
                if (openId.isAnErrorResponse(s)) {
                    response.setStatus(400);
                }
                out.print(s);
                out.flush();
            }
        } catch (OpenIdException e) {
            e.printStackTrace();
            response.sendError(500, e.getMessage());
        }
    }

    public static String getLoggedIn(HttpServletRequest request) {
        String o = (String) request.getSession(true).getAttribute("username");

        if (o != null) {
            return o;
        }
        String authKey = CookieUtils.getCookieValue(request, "authKey", null);

        if (authKey != null) {
            String username = CookieUtils.getCookieValue(request, "username",
                    null);

            if (username != null) {
                o = getUserManager().getRememberedUser(username, authKey);
                if (o != null) {
                    request.getSession(true).setAttribute("username", o);
                }
            }

        }

        return o;
    }

    public static void setLoggedIn(HttpServletRequest request, String username) {
        request.getSession(true).setAttribute("username", username);
    }

    private void returnError(String query, HttpServletResponse response)
            throws ServletException, IOException {
        Map map = RequestFactory.parseQuery(query);
        String returnTo = (String) map.get("openid.return_to");
        boolean goodReturnTo = false;
        try {
            URL url = new URL(returnTo);
            goodReturnTo = true;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        if (goodReturnTo) {
            String s = "?openid.ns:http://specs.openid.net/auth/2.0&openid.mode=error&openid.error=BAD_REQUEST";

            s = response.encodeRedirectURL(returnTo + s);
            response.sendRedirect(s);
        } else {
            PrintWriter out = response.getWriter();

            String s = "ns:http://specs.openid.net/auth/2.0\n&mode:error&error:BAD_REQUEST\n";

            int len = s.length();
            response.setHeader("Content-Length", Integer.toString(len));
            response.setStatus(400);
            out.print(s);
            out.flush();
        }
    }

    public void log(String s) {
        System.out.println(s);
    }

    public static void idClaimed(HttpSession session, String claimedId) {
        session.setAttribute("idClaimed", claimedId);
    }

    public static UserManager getUserManager() {
        return userManager;
    }
}