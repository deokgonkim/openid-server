package net.dgkim.openid;

import java.util.Date;

public abstract interface Nonce {
    public abstract String getNonce();

    public abstract void setCheckedDate(Date paramDate);
}