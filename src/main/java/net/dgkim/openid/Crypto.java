package net.dgkim.openid;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Crypto {
    private DiffieHellman dh;
    private static final Logger log = Logger.getLogger("net.dgkim.openid");
    private static SecureRandom random;

    public static byte[] sha1(byte[] text) throws NoSuchAlgorithmException {
        MessageDigest d = MessageDigest.getInstance("SHA-1");

        return d.digest(text);
    }

    public static byte[] sha256(byte[] text) throws NoSuchAlgorithmException {
        MessageDigest d = MessageDigest.getInstance("SHA-256");

        return d.digest(text);
    }

    public static byte[] hmacSha1(byte[] key, byte[] text)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return hmacShaX("HMACSHA1", key, text);
    }

    public static byte[] hmacSha256(byte[] key, byte[] text)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return hmacShaX("HMACSHA256", key, text);
    }

    private static byte[] hmacShaX(String keySpec, byte[] key, byte[] text)
            throws InvalidKeyException, NoSuchAlgorithmException {
        SecretKey sk = new SecretKeySpec(key, keySpec);
        Mac m = Mac.getInstance(sk.getAlgorithm());
        m.init(sk);

        return m.doFinal(text);
    }

    static {
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No secure random available.");
        }
    }

    public static String generateHandle() {
        return UUID.randomUUID().toString();
    }

    public static String generateCrumb() {
        byte[] b = new byte[4];
        random.nextBytes(b);

        return convertToString(b);
    }

    public byte[] generateRandom(String s) {
        int len = 0;
        if (AssociationRequest.DH_SHA1.equals(s))
            len = 20;
        else if (AssociationRequest.DH_SHA256.equals(s))
            len = 32;
        else if (AssociationRequest.NO_ENCRYPTION.equals(s))
            len = 0;
        else if (AssociationRequest.HMAC_SHA1.equals(s))
            len = 20;
        else if (AssociationRequest.HMAC_SHA256.equals(s)) {
            len = 32;
        }
        byte[] result = new byte[len];
        random.nextBytes(result);

        return result;
    }

    public void setDiffieHellman(BigInteger mod, BigInteger gen) {
        this.dh = new DiffieHellman(mod, gen);
    }

    public void setDiffieHellman(DiffieHellman dh) {
        this.dh = dh;
    }

    public BigInteger getPublicKey() {
        if (this.dh == null) {
            throw new IllegalArgumentException("DH not yet initialized");
        }

        return this.dh.getPublicKey();
    }

    public byte[] generateSecret(String sessionType) {
        return generateRandom(sessionType);
    }

    public byte[] decryptSecret(BigInteger consumerPublic, byte[] secret)
            throws OpenIdException {
        return encryptSecret(consumerPublic, secret);
    }

    public byte[] encryptSecret(BigInteger consumerPublic, byte[] secret)
            throws OpenIdException {
        if (this.dh == null) {
            throw new IllegalArgumentException("No DH implementation set");
        }
        byte[] xoredSecret = null;
        try {
            xoredSecret = this.dh.xorSecret(consumerPublic, secret);

            return xoredSecret;
        } catch (NoSuchAlgorithmException e) {
            throw new OpenIdException(e);
        }
    }

    public static byte[] convertToBytes(String s) {
        BASE64Decoder base64decoder = new BASE64Decoder();
        ByteArrayInputStream bais = new ByteArrayInputStream(s.getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] abyte0 = null;
        try {
            base64decoder.decodeBuffer(bais, baos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        abyte0 = baos.toByteArray();

        return abyte0;
    }

    public static String convertToString(byte[] b) {
        BASE64Encoder base64encoder = new BASE64Encoder();
        ByteArrayInputStream bais = new ByteArrayInputStream(b);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] abyte1 = null;
        try {
            base64encoder.encodeBuffer(bais, baos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        abyte1 = baos.toByteArray();

        return new String(abyte1).replaceAll("\n", "").trim();
    }

    public static String convertToString(BigInteger b) {
        return convertToString(b.toByteArray());
    }

    public static BigInteger convertToBigIntegerFromString(String s) {
        BASE64Decoder base64decoder = new BASE64Decoder();
        ByteArrayInputStream bais = new ByteArrayInputStream(s.getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] abyte0 = null;
        try {
            base64decoder.decodeBuffer(bais, baos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        abyte0 = baos.toByteArray();

        return new BigInteger(abyte0);
    }
}