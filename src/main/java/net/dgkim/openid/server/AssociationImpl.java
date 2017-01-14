package net.dgkim.openid.server;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;
import net.dgkim.openid.Association;
import net.dgkim.openid.AssociationRequest;
import net.dgkim.openid.Crypto;

public class AssociationImpl implements Association {
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private Long id;
    private String mode;
    private String handle;
    private String secret;
    private Date issuedDate;
    private Long lifetime;
    private String associationType;
    private String error;
    private String sessionType;
    private byte[] encryptedMacKey;
    private BigInteger publicKey;

    public boolean isSuccessful() {
        return (this.error == null);
    }

    public boolean isEncrypted() {
        return ((AssociationRequest.DH_SHA1.equals(this.sessionType)) || (AssociationRequest.DH_SHA256
                .equals(this.sessionType)));
    }

    public Long getId() {
        return this.id;
    }

    public String getSecret() {
        return this.secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMode() {
        return this.mode;
    }

    public void setMode(String s) {
        this.mode = s;
    }

    public String getHandle() {
        return this.handle;
    }

    public void setHandle(String s) {
        this.handle = s;
    }

    public Date getIssuedDate() {
        return this.issuedDate;
    }

    public void setIssuedDate(Date issuedDate) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date tmp = issuedDate;
        sdf.format(tmp);
        this.issuedDate = tmp;
    }

    public Long getLifetime() {
        return this.lifetime;
    }

    public void setLifetime(Long lifetime) {
        this.lifetime = lifetime;
    }

    public String getAssociationType() {
        return this.associationType;
    }

    public void setAssociationType(String s) {
        this.associationType = s;
    }

    public String toString() {
        String s = "[Association secret=" + this.secret;
        if (this.encryptedMacKey != null) {
            s = s + ", encrypted secret="
                    + Crypto.convertToString(this.encryptedMacKey);
        }

        if (this.publicKey != null) {
            s = s + ", public key=" + Crypto.convertToString(this.publicKey);
        }
        s = s + ", type=" + this.associationType + ", issuedDate="
                + this.issuedDate + "]";

        return s;
    }

    public String getError() {
        return this.error;
    }

    public String getErrorCode() {
        throw new RuntimeException("nyi");
    }

    public void setSessionType(String sessionType) {
        this.sessionType = sessionType;
    }

    public String getSessionType() {
        return this.sessionType;
    }

    public void setMacKey(byte[] macKey) {
        this.secret = Crypto.convertToString(macKey);
    }

    public byte[] getMacKey() {
        return Crypto.convertToBytes(this.secret);
    }

    public void setEncryptedMacKey(byte[] b) {
        this.encryptedMacKey = b;
    }

    public byte[] getEncryptedMacKey() {
        return this.encryptedMacKey;
    }

    public void setPublicDhKey(BigInteger pk) {
        this.publicKey = pk;
    }

    public BigInteger getPublicDhKey() {
        return this.publicKey;
    }

    public boolean hasExpired() {
        Calendar now = Calendar.getInstance();
        log.fine("now: " + now.toString());
        Calendar expired = Calendar.getInstance();
        log.fine("issuedDate: " + this.issuedDate.toString());
        expired.setTime(this.issuedDate);
        expired.add(13, this.lifetime.intValue());
        log.fine("expired: " + expired.toString());
        log.fine("now.after(expired): " + now.after(expired));

        return now.after(expired);
    }
}