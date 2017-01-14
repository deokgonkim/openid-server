package net.dgkim.openid.util;

public class DependencyUtils {
    public static Object newInstance(String className) {
        try {
            return Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("Not found " + className);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("No access to " + className);
        } catch (InstantiationException e) {
            throw new IllegalArgumentException("Cannot instantiate "
                    + className);
        }
    }
}