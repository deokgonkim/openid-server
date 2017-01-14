package net.dgkim.openid;

public class OpenIdException extends Exception {
    private static final long serialVersionUID = 28732439387623L;

    public OpenIdException(String s) {
        super(s);
    }

    public OpenIdException(Exception e) {
        super(e);
    }

    public OpenIdException(String s, Exception e) {
        super(s, e);
    }

    public String getMessage() {
        Throwable t = getCause();
        if (t != null) {
            return t.getMessage();
        }

        return super.getMessage();
    }
}