package net.dgkim.openid;

import net.dgkim.openid.util.DependencyUtils;

public class StoreFactory {
    public static boolean hasType(String storeType) {
        return "db".equals(storeType);
    }

    public static Store getInstance(String className) {
        return ((Store) DependencyUtils.newInstance(className));
    }
}