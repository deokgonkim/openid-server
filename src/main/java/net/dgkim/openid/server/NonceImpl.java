package net.dgkim.openid.server;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;
import net.dgkim.openid.Nonce;

public class NonceImpl implements Nonce {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private Long id;
    private String nonce;
    private Date checkedDate;

    public Long getId() {
        return this.id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNonce() {
        return this.nonce;
    }

    public void setNonce(String s) {
        this.nonce = s;
    }

    public Date getCheckedDate() {
        return this.checkedDate;
    }

    public void setCheckedDate(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date tmp = date;
        sdf.format(tmp);
        this.checkedDate = tmp;
    }

    public String toString() {
        return "[Nonce nonce=" + this.nonce + ", checked=" + this.checkedDate
                + "]";
    }
}