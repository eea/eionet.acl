package eionet.acl;

import java.io.IOException;

/**
 *
 * @author Ervis Zyka <ez@eworx.gr>
 */
public interface AclInitializer {
    void initializeAcl(String AclDestUrl) throws IOException;
    boolean isAclInitiazed(String AclDestUrl);

}
