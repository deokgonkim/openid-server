package net.dgkim.openid.server.servlet;

import java.io.IOException;
import java.net.URLDecoder;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserUrlFilter implements Filter {
    private static Logger log = Logger.getLogger("net.dgkim.openid");
    private String idJsp;

    public void init(FilterConfig filterConfig) throws ServletException {
        this.idJsp = filterConfig.getInitParameter("idJsp");
    }

    public void doFilter(ServletRequest req, ServletResponse res,
            FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String s = request.getServletPath();
        s = URLDecoder.decode(s, "utf-8");
        log.info("servletpath: " + s);
        String[] sections = s.split("/");
        log.info("sections.length: " + sections.length);
        String redir = "";
        String contextPath = request.getContextPath();
        if (sections.length >= 2)
            for (int i = 0; i < sections.length; ++i) {
                String section = sections[i];
                log.info("section: " + section);
                if (section.equals("user")) {
                    String username = sections[(i + 1)];
                    log.info("username: " + username);
                    log.info("forwarding to: " + contextPath + this.idJsp);
                    request.setAttribute("username", username);
                    forward(request, response, this.idJsp);

                    return;
                }
            }
        filterChain.doFilter(req, res);
    }

    public void destroy() {
    }

    private void forward(HttpServletRequest request,
            HttpServletResponse response, String path) throws IOException,
            ServletException {
        request.getRequestDispatcher(path).forward(request, response);
    }
}