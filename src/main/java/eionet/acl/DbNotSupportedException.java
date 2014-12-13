/*
 * Created on 5.05.2006
 */
package eionet.acl;

/**
 * Database not supported Exception.
 *
 * @author jaanus
 */
public class DbNotSupportedException extends Exception {

    /**
     *
     *
     */
    public DbNotSupportedException() {
        super("");
    }

    /**
     *
     * @param s
     */
    public DbNotSupportedException(String s) {
        super(s);
    }
}
