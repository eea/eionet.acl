package eionet.acl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.ResourceBundle;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests various methods of RemoteService.
 *
 * @author Søren Roug
 *
 */
public class RemoteServiceTest extends ACLDatabaseTestCase {

    RemoteService rs;

    @Before
    public void logIn() throws Exception {
        AppUser myUser = new AppUser();
        myUser.authenticate("enriko", "mi6");

        rs = new RemoteService(myUser);
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
        Hashtable<String, Vector> groups = rs.getLocalGroups();

        Vector appAdminMembers = groups.get("app_admin");
        assertTrue(appAdminMembers.contains("jaanus2"));
        //System.out.println(groups);
    }


    /**
     * Enriko doesn't have 'c' permission.
     */
    @Test(expected=SignOnException.class)
    public void setAclWithNoControl() throws Exception {
        Hashtable<String, Object> aclInfo = new Hashtable<String, Object>();

        aclInfo.put("name", "/eeaprojects");
        aclInfo.put("description", "Blåbærgrød");

        Vector<Hashtable<String, String>> aclEntries = new Vector<Hashtable<String, String>>();

        Hashtable<String, String> row1 = constructAclEntry("user", "enriko", "c,v");
        aclEntries.add(row1);
        aclInfo.put("entries", aclEntries);
        rs.setAclInfo(aclInfo);

    }

    /**
     * heinlaid has 'c' permission.
     */
    @Test
    public void setAclWithJaanus() throws Exception {
        AppUser myUser = new AppUser();
        myUser.authenticate("heinlaid", "mi6");

        rs = new RemoteService(myUser);

        Hashtable<String, Object> savedAclInfo = new Hashtable<String, Object>();
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
    private Hashtable constructAclEntry(String principalType, String principalId, String permissions) {

        Hashtable<String, String> h = new Hashtable<String, String>();
        h.put("acltype", "object"); // hard-coded
        h.put("type", principalType);
        h.put("id", principalId);
        h.put("perms", permissions);

        return h;
    }

}
