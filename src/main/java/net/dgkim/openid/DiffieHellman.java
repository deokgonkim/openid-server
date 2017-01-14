package net.dgkim.openid;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

public class DiffieHellman {
    private BigInteger modulus;
    private BigInteger generator;
    private BigInteger privateKey;
    private BigInteger publicKey;
    private static final Logger log = Logger.getLogger("net.dgkim.openid");

    public static final BigInteger DEFAULT_MODULUS = new BigInteger(
            "155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443");

    public static final BigInteger DEFAULT_GENERATOR = BigInteger.valueOf(2);
    private static SecureRandom random;

    private DiffieHellman() {
    }

    public static DiffieHellman getDefault() {
        BigInteger p = DEFAULT_MODULUS;
        BigInteger g = DEFAULT_GENERATOR;

        return new DiffieHellman(p, g);
    }

    static {
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No secure random available!");
        }
    }

    public BigInteger getPrivateKey() {
        return this.privateKey;
    }

    public BigInteger getPublicKey() {
        return this.publicKey;
    }

    public DiffieHellman(BigInteger mod, BigInteger gen) {
        this.modulus = ((mod != null) ? mod : DEFAULT_MODULUS);
        this.generator = ((gen != null) ? gen : DEFAULT_GENERATOR);

        int bits = this.modulus.bitLength();
        BigInteger max = this.modulus.subtract(BigInteger.ONE);
        while (true) {
            BigInteger pkey = new BigInteger(bits, random);
            if (pkey.compareTo(max) < 0) {
                if (pkey.compareTo(BigInteger.ONE) > 0) {
                    this.privateKey = pkey;
                    this.publicKey = this.generator.modPow(this.privateKey,
                            this.modulus);
                    return;
                }
            }
        }
    }

    public static DiffieHellman recreate(BigInteger privateKey,
            BigInteger modulus) {
        if ((privateKey == null) || (modulus == null)) {
            throw new IllegalArgumentException("Null parameter");
        }
        DiffieHellman dh = new DiffieHellman();
        dh.setPrivateKey(privateKey);
        dh.setModulus(modulus);

        return dh;
    }

    private void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    private void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getSharedSecret(BigInteger composite) {
        return composite.modPow(this.privateKey, this.modulus);
    }

    public byte[] xorSecret(BigInteger otherPublic, byte[] secret)
            throws NoSuchAlgorithmException {
        byte[] hashed;
        if (otherPublic == null) {
            throw new IllegalArgumentException("otherPublic cannot be null");
        }

        BigInteger shared = getSharedSecret(otherPublic);

        if (secret.length == 32)
            hashed = Crypto.sha256(shared.toByteArray());
        else {
            hashed = Crypto.sha1(shared.toByteArray());
        }

        if (secret.length != hashed.length) {
            log.fine("invalid secret byte[] length: secret=" + secret.length
                    + ", hashed=" + hashed.length);

            throw new RuntimeException("nyi");
        }

        byte[] result = new byte[secret.length];
        for (int i = 0; i < result.length; ++i) {
            result[i] = (byte) (hashed[i] ^ secret[i]);
        }

        return result;
    }
}