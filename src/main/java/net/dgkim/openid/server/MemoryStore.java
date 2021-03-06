package net.dgkim.openid.server;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;
import net.dgkim.openid.Association;
import net.dgkim.openid.AssociationRequest;
import net.dgkim.openid.Crypto;
import net.dgkim.openid.Nonce;
import net.dgkim.openid.OpenIdException;
import net.dgkim.openid.Store;

public class MemoryStore extends Store {
    public static long DEFAULT_LIFESPAN = 300L;

    private static List associationList = new ArrayList();
    private static List nonceList = new ArrayList();
    private long associationLifetime;

    private void $init$() {
        this.associationLifetime = DEFAULT_LIFESPAN;
    }

    public Association generateAssociation(AssociationRequest req, Crypto crypto)
            throws OpenIdException {
        AssociationImpl a = new AssociationImpl();
        a.setMode("unused");
        a.setHandle(Crypto.generateHandle());
        a.setSessionType(req.getSessionType());

        byte[] secret = null;
        if (req.isNotEncrypted()) {
            secret = crypto.generateSecret(req.getAssociationType());
        } else {
            secret = crypto.generateSecret(req.getSessionType());
            crypto.setDiffieHellman(req.getDhModulus(), req.getDhGenerator());
            byte[] encryptedSecret = crypto.encryptSecret(
                    req.getDhConsumerPublic(), secret);

            a.setEncryptedMacKey(encryptedSecret);
            a.setPublicDhKey(crypto.getPublicKey());
        }
        a.setMacKey(secret);
        a.setIssuedDate(new Date());
        a.setLifetime(new Long(this.associationLifetime));

        a.setAssociationType(req.getAssociationType());

        return a;
    }

    public void saveAssociation(Association a) {
        associationList.add(a);
    }

    public void saveNonce(Nonce n) {
        nonceList.add(n);
    }

    public void deleteAssociation(Association a) {
        throw new RuntimeException("not yet implemented");
    }

    public Association findAssociation(String handle) throws OpenIdException {
        if (handle == null) {
            return null;
        }
        ListIterator li = associationList.listIterator();
        while (li.hasNext()) {
            Association a = (Association) li.next();
            if (handle.equals(a.getHandle())) {
                return a;
            }
        }

        return null;
    }

    public Nonce findNonce(String nonce) throws OpenIdException {
        if (nonce == null) {
            return null;
        }
        ListIterator li = nonceList.listIterator();
        while (li.hasNext()) {
            Nonce n = (Nonce) li.next();
            if (nonce.equals(n.getNonce())) {
                return n;
            }
        }

        return null;
    }

    public Nonce generateNonce(String nonce) throws OpenIdException {
        NonceImpl n = new NonceImpl();
        n.setNonce(nonce);
        n.setCheckedDate(new Date());

        return n;
    }

    public void setAssociationLifetime(long associationLifetime) {
        this.associationLifetime = associationLifetime;
    }

    public MemoryStore() {
        $init$();
    }
}