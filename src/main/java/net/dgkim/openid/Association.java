package net.dgkim.openid;

import java.math.BigInteger;
import java.util.Date;

public abstract interface Association {
    public abstract boolean isSuccessful();

    public abstract String getError();

    public abstract String getErrorCode();

    public abstract String getHandle();

    public abstract void setHandle(String paramString);

    public abstract void setIssuedDate(Date paramDate);

    public abstract void setLifetime(Long paramLong);

    public abstract Long getLifetime();

    public abstract String getAssociationType();

    public abstract void setAssociationType(String paramString);

    public abstract String getSessionType();

    public abstract void setSessionType(String paramString);

    public abstract byte[] getMacKey();

    public abstract BigInteger getPublicDhKey();

    public abstract void setPublicDhKey(BigInteger paramBigInteger);

    public abstract boolean isEncrypted();

    public abstract void setEncryptedMacKey(byte[] paramArrayOfByte);

    public abstract byte[] getEncryptedMacKey();

    public abstract boolean hasExpired();
}