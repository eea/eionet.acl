package eionet.acl;

/**
 * ACL not found exception.
 *
 * @author jaanus
 *
 */
public class AclNotFoundException extends SignOnException {

    /**
     *
     * @param message
     */
    public AclNotFoundException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param cause
     */
    public AclNotFoundException(String message, Throwable cause) {
        super(cause, message);
    }
}
