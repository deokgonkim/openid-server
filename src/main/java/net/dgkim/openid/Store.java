package net.dgkim.openid;

public abstract class Store {
    public abstract Association generateAssociation(
            AssociationRequest paramAssociationRequest, Crypto paramCrypto)
            throws OpenIdException;

    public abstract void deleteAssociation(Association paramAssociation);

    public abstract void saveAssociation(Association paramAssociation);

    public abstract Association findAssociation(String paramString)
            throws OpenIdException;

    public abstract Nonce findNonce(String paramString) throws OpenIdException;

    public abstract void saveNonce(Nonce paramNonce);

    public abstract Nonce generateNonce(String paramString)
            throws OpenIdException;
}