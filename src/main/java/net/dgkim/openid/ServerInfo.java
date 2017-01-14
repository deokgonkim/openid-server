package net.dgkim.openid;

public class ServerInfo {
    private String urlEndPoint;
    private Store store;
    private Crypto crypto;

    public ServerInfo(String urlEndPoint, Store store, Crypto crypto) {
        this.urlEndPoint = urlEndPoint;
        this.store = store;
        this.crypto = crypto;
    }

    public String getUrlEndPoint() {
        return this.urlEndPoint;
    }

    public Store getStore() {
        return this.store;
    }

    public Crypto getCrypto() {
        return this.crypto;
    }
}