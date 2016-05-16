package eionet.acl;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;
import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Aris Katsanas <aka@eworx.gr>
 */
public class AclPropertiesTest {
    
    private AclProperties aclProperties;
    
    @Before
    public void setUp() throws Exception {
        this.aclProperties = new AclProperties();
        this.aclProperties = AclPropertiesBuilder.AclPropertiesBuilder ( "acl.properties" );
    }
    
     /**
     * Test that the AclProperties Object is correctly built from a properties file.
     */
    @Test
    public void testPropertiesLoading() {
        assertEquals( this.aclProperties.getOwnerPermission(), "c" );
        assertEquals( this.aclProperties.getFileLocalgroups(), "target/test-classes/acl.group" );
        assertEquals( this.aclProperties.getFilePermissions(), "target/test-classes/acl.prms" );
        assertEquals( this.aclProperties.getAuthenticatedAccess(), "authenticated" );
        assertEquals( this.aclProperties.getFileLocalusers(), "target/test-classes/users.xml" );
        assertEquals( this.aclProperties.getInitialAdmin(), null );
    }
    
}
