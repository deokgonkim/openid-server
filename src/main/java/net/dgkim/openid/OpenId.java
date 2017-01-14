package net.dgkim.openid;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.logging.Logger;

public class OpenId {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private ServerInfo serverInfo;

    public OpenId(ServerInfo serverInfo) {
        this.serverInfo = serverInfo;
    }

    public boolean canHandle(String query) {
        boolean ret = false;
        
        try {
            RequestFactory.parse(query);
            ret = true;
        } catch (UnsupportedEncodingException e) {
            log.finer(e.getMessage());
            e.printStackTrace();
        } catch (OpenIdException e) {
            log.finer(e.getMessage());
            e.printStackTrace();
        }
        
        return ret;
    }

    public ServerInfo getServerInfo() {
        return this.serverInfo;
    }

    public String handleRequest(Map map) throws OpenIdException {
        throw new RuntimeException("nyi");
    }

    public boolean isAssociationRequest(String query) {
        boolean ret = false;
        try {
            Request req = RequestFactory.parse(query);
            return req instanceof AssociationRequest;
        } catch (OpenIdException e) {
            log.finer(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            log.finer(e.getMessage());
        }
        return ret;
    }

    public boolean isAuthenticationRequest(String query) {
        boolean ret = false;
        try {
            Request req = RequestFactory.parse(query);
            return req instanceof AuthenticationRequest;
        } catch (OpenIdException e) {
            log.finer(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            log.finer(e.getMessage());
        }
        return ret;
    }

    public boolean isCheckAuthenticationRequest(String query) {
        boolean ret = false;
        try {
            Request req = RequestFactory.parse(query);
            return req instanceof CheckAuthenticationRequest;
        } catch (OpenIdException e) {
            log.finer(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            log.finer(e.getMessage());
        }
        return ret;
    }

    public String handleRequest(String query) throws OpenIdException {
        Request req = null;
        try {
            req = RequestFactory.parse(query);
        } catch (UnsupportedEncodingException e) {
            log.warning("exception=" + e);
            throw new OpenIdException(e);
        }
        Response resp = req.processUsing(this.serverInfo);
        if (req instanceof AuthenticationRequest) {
            return resp.toUrlString();
        }
        return resp.toPostString();
    }

    public boolean isAnErrorResponse(String s) {
        try {
            Response resp = ResponseFactory.parse(s);

            return ((resp.getError() != null) ? true : false);
        } catch (OpenIdException e) {
            e.printStackTrace();
        }
        return false;
    }
}