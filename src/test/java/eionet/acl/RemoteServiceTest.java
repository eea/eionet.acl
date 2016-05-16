package eionet.acl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import java.util.Hashtable;
import java.util.Vector;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Tests various methods of RemoteService.
 *
 * @author Søren Roug
 *
 */
public class RemoteServiceTest extends ACLDatabaseTestCase {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    RemoteService rs;
    private AclProperties aclProperties;

    @Before
    public void logIn() throws Exception {
        AppUser myUser = new AppUser();
        myUser.authenticateForTest("enriko");

        rs = new RemoteService(myUser);
    }
    
    @Before
    public void setUp() throws Exception {
        this.aclProperties = new AclProperties();
        this.aclProperties = AclPropertiesBuilder.AclPropertiesBuilder ( "acl.properties" );
    }

    /**
     */
    @Test
    public void getAllAcls() throws Exception {

        Vector acls = rs.getAcls();
        assertEquals("/", acls.get(0));
        assertEquals("/dcctest", acls.get(1));
        assertEquals("/eeaprojects", acls.get(2));
        assertEquals("/localgroups", acls.get(3));
        assertEquals("/whatever", acls.get(4));
        /*
        for (Object aclName : acls) {
            System.out.println((String) aclName);
        }
        System.out.println(acls);
        */
    }

    @Test
    public void testChildrenAcls() throws Exception {

        Vector acls = rs.getChildrenAcls("/");
        assertEquals("/dcctest", acls.get(0));
        assertEquals("/eeaprojects", acls.get(1));
        assertEquals("/localgroups", acls.get(2));
        assertEquals("/whatever", acls.get(3));
    }

    @Test
    public void testLocalGroups() throws Exception {
        AppUser myUser = new AppUser();
        myUser.authenticateForTest("ander");

        rs = new RemoteService(myUser);

        Hashtable<String, Vector<String>> savedGroups = rs.getLocalGroups();

        Vector appAdminMembers = savedGroups.get("app_admin");
        assertTrue(appAdminMembers.contains("jaanus2"));
        //System.out.println(groups);

        Hashtable<String, Vector<String>> newGroups = new Hashtable<String, Vector<String>>();

        Vector<String> adminMembers = new Vector<String>();
        adminMembers.add("ander");
        newGroups.put("app_admin", adminMembers);

        Vector<String> beatlesMembers = new Vector<String>();
        beatlesMembers.add("john");
        beatlesMembers.add("paul");
        beatlesMembers.add("george");
        beatlesMembers.add("ringo");
        newGroups.put("beatles", beatlesMembers);

        assertEquals("OK", rs.setLocalGroups(newGroups));
        Hashtable<String, Vector<String>> expectedGroups = rs.getLocalGroups();
        assertTrue(expectedGroups.get("beatles").contains("ringo"));
        assertFalse(expectedGroups.get("beatles").contains("pete"));
        
        rs.setLocalGroups(savedGroups);
    }


    /**
     * Enriko doesn't have 'c' permission.
     */
    @Test
    public void setAclWithNoControl() throws Exception {
        Hashtable<String, Object> aclInfo = new Hashtable<String, Object>();

        aclInfo.put("name", "/eeaprojects");
        aclInfo.put("description", "Blåbærgrød");

        Vector<Hashtable<String, String>> aclEntries = new Vector<Hashtable<String, String>>();

        Hashtable<String, String> row1 = constructAclEntry("user", "enriko", "c,v");
        aclEntries.add(row1);
        aclInfo.put("entries", aclEntries);

        thrown.expect(SignOnException.class);
        rs.setAclInfo(aclInfo);
    }

    /**
     * heinlaid has 'c' permission.
     */
    @Test
    public void setAclWithJaanus() throws Exception {
        AppUser myUser = new AppUser();
        myUser.authenticateForTest("heinlaid");

        rs = new RemoteService(myUser);

        Hashtable<String, Object> savedAclInfo;
        savedAclInfo = rs.getAclInfo("/eeaprojects");

        Hashtable<String, Object> aclInfo = new Hashtable<String, Object>();

        aclInfo.put("name", "/eeaprojects");
        aclInfo.put("description", "Blåbærgrød");

        Vector<Hashtable<String, String>> aclEntries = new Vector<Hashtable<String, String>>();

        Hashtable<String, String> row1 = constructAclEntry("user", "enriko", "c,v");
        aclEntries.add(row1);
        Hashtable<String, String> row2 = constructAclEntry("user", "heinlaid", "c,v");
        aclEntries.add(row2);

        aclInfo.put("entries", aclEntries);
        assertEquals("OK", rs.setAclInfo(aclInfo));
        assertTrue(AccessController.hasPermission("enriko", "/eeaprojects", "c"));
        assertFalse(AccessController.hasPermission("enriko", "/eeaprojects", "d"));
        // Bring it back to the original
        assertEquals("OK", rs.setAclInfo(savedAclInfo));
        assertFalse(AccessController.hasPermission("enriko", "/eeaprojects", "c"));

    }
    /**
     * Constructs a hashtable representing an ACL entry.
     *
     * @param principalType principal type
     * @param principalId principal ID
     * @param permissions permissions in CSV format
     * @return entry hash
     */
    private Hashtable<String, String> constructAclEntry(String principalType, String principalId, String permissions) {

        Hashtable<String, String> h = new Hashtable<String, String>();
        h.put("acltype", "object"); // hard-coded
        h.put("type", principalType);
        h.put("id", principalId);
        h.put("perms", permissions);

        return h;
    }

}
