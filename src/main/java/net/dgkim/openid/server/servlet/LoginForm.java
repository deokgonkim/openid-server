package net.dgkim.openid.server.servlet;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URLDecoder;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import net.dgkim.openid.server.MemoryUserManager;
import net.dgkim.openid.server.User;
import net.dgkim.openid.util.CookieUtils;
import net.dgkim.openid.util.UrlUtils;
import org.apache.commons.lang.RandomStringUtils;

public class LoginForm extends HttpServlet {
    private static final String CONTENT_TYPE = "text/html; charset=UTF-8";

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    public void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession();
        RequestDispatcher dispatcher = null;
        String errorMsg = null;

        String username = request.getParameter("username");
        if (username != null) {
            if (authenticate(request, username,
                    request.getParameter("password"),
                    request.getParameter("newuser"))) {
                String claimedId = (String) session
                        .getAttribute("openid.claimed_id");

                if (claimedId != null) {
                    String usernameFromClaimedId = claimedId
                            .substring(claimedId.lastIndexOf("/") + 1);

                    System.out.println("usernamefromurl: "
                            + usernameFromClaimedId);

                    if (username.equals(usernameFromClaimedId)) {
                        OpenIdServlet.idClaimed(session, claimedId);
                        String query = request.getParameter("query");

                        String baseUrl = UrlUtils.getBaseUrl(request);
                        String openIdServer = baseUrl + "/login";
                        response.sendRedirect(openIdServer + "?"
                                + URLDecoder.decode(query));

                        return;
                    }
                    errorMsg = "You do not own the claimed identity.";
                }

                if (request.getParameter("rememberMe") != null) {
                    String secretKey = RandomStringUtils.randomAlphanumeric(128);

                    CookieUtils.setCookie(response, "username", username);

                    CookieUtils.setCookie(response, "authKey", secretKey);

                    userManager().remember(username, secretKey);
                }
            } else {
                errorMsg = "Invalid login.";
            }
        }
        dispatcher = request.getRequestDispatcher("/login.jsp");

        request.setAttribute("errorMsg", errorMsg);
        request.setAttribute("query", getParam(request, "query"));
        request.setAttribute("realm", getParam(request, "openid.realm"));

        dispatcher.forward(request, response);
    }

    private MemoryUserManager userManager() {
        return ((MemoryUserManager) OpenIdServlet.getUserManager());
    }

    private String getParam(HttpServletRequest request, String s) {
        String ret = (String) request.getAttribute(s);
        if (ret == null) {
            ret = request.getParameter(s);
        }

        if (ret == null) {
            HttpSession session = request.getSession(true);
            ret = (String) session.getAttribute(s);
        }

        return ret;
    }

    private boolean authenticate(HttpServletRequest request, String username,
            String password, String newuser) {
        User user = userManager().getUser(username);
        if (user == null) {
            if (newuser != null) {
                user = new User(username, password);
                userManager().save(user);
                System.out.println("created new user: " + username);
            } else {
                return false;
            }
        }
        if (user.getPassword().equals(password)) {
            request.getSession(true).setAttribute("username",
                    user.getUsername());

            request.getSession(true).setAttribute("user", user);

            return true;
        }

        return false;
    }
}