package eionet.acl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Jaanus Heinlaid
 *
 */
public class AccessControlListTest extends ACLDatabaseTestCase {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Tests various methods of AccessControlListIF, but also makes sure the code is still able to handle ACL files that are not in
     * XML format, because the tests here are run on _whatever.acl, which is indeed in the old format.
     */
    @Test
    public void testAclsInFiles() throws Exception {

        AccessControlListIF acl = AccessController.getAcl("/whatever");
        assertNotNull("Acl \"/whatever\" must not be null", acl);

        Vector entryRows = acl.getEntryRows();
        assertNotNull("acl.getEntryRows() must not be null", entryRows);
        assertEquals("expected size of acl.getEntryRows() is 3", entryRows.size(), 3);

        String description = acl.getDescription();
        assertNotNull("acl.getDescription() must not be null", description);
        assertEquals("acl.getDescription() must equal to \"whatever_description\"", description, "whatever_description");

        List<HashMap<String, String>> docAndDdcEntries = acl.getDOCAndDCCEntries();
        assertNotNull("acl.getDocEntries() must not be null", docAndDdcEntries);
        assertEquals("acl.getDocEntries() size must be 1", docAndDdcEntries.size(), 1);

        assertFalse("jaanus2 must not have permission 'v'", acl.checkPermission("jaanus2", "v"));

        boolean unknownPermission = false;
        try {
            acl.checkPermission("jaanus2", "a");
        } catch (SignOnException e) {
            if (e.toString().toLowerCase().indexOf("unknown permission") > 0)
                unknownPermission = true;
        }
        assertTrue("Was expecting 'a' to be unknown permission", unknownPermission);

        assertTrue("Owner name must be \"/whatever\"", acl.isOwner("/whatever"));

        assertEquals("expected the ACL's mechanism to be TEXT_FILE", acl.mechanism(), AccessControlListIF.TEXT_FILE);
    }

    /**
     * Test that you can add an ACL called /whatever/123
     *
     */
    @Test
    public void testAclsInDatabase() throws Exception {

        String aclPath = "/whatever/123";

        try {
            AccessController.addAcl(aclPath, "jaanus1", "whatever123description");
        } catch (SignOnException e) {
            fail("Was not expecting this failure when creating a new acl in the database: " + e.toString());
        }

        // now try to create again, to make sure an exception is thrown
        try {
            AccessController.addAcl(aclPath, "jaanus1", "whatever123description");
            fail("Creation of an existing ACL should not have passed without an exception thrown");
        } catch (SignOnException e) {
            //it is a test
        }

        // now read the freshly created ACL
        AccessControlListIF acl = null;
        try {
            acl = AccessController.getAcl(aclPath);
        } catch (SignOnException e) {
            fail("Was not expecting this failure when reading acl from the database: " + e.toString());
        }
        assertNotNull("The freshly created acl must not be null", acl);
        assertEquals("The mechanism of the freshly created acl must be 'database'", acl.mechanism(), AccessControlListIF.DB);

        try {
            // the freshly created ACL must contain one entry row, created by the DOC principle, and it must give permissions to
            // "jaanus2"
            Vector entryRows = acl.getEntryRows();
            assertTrue("the freshly created ACL must contain one entry row, created by the DOC principle", entryRows != null
                    && entryRows.size() == 1);
            assertTrue("jaanus2 must have 'u' permission in the freshly created ACL", acl.checkPermission("jaanus2", "u"));

            // the owner of the freshly created ACL must be "jaanus1"
            assertTrue("the owner of the freshly created ACL must be \"jaanus1\"", acl.isOwner("jaanus1"));

            // create some new entries in the freshly created ACL and then reset (and read the ACL again),
            // because ACLs are not refresh automatically in the memeory
            Vector<Hashtable<String, String>> entries = new Vector<Hashtable<String, String>>();
            entries.add(constructAclEntry("user", "jensen", "v,i"));
            entries.add(constructAclEntry("localgroup", "app_user", "x"));
            acl.setAclEntries(entries);
            AccessController.reset();
            acl = AccessController.getAcl(aclPath);

            assertFalse("jaanus2 must not have the 'u' permission any more", acl.checkPermission("jaanus2", "u"));
            assertTrue("jensen must have the 'i' permission now", acl.checkPermission("jensen", "i"));
            assertTrue("risto must have the 'x' permission now (being in 'app_user' group)", acl.checkPermission("risto", "x"));
        } catch (SignOnException e) {
            e.printStackTrace();
            fail("Was not expecting this exception: " + e.toString());
        }
        // Clean up
        AccessController.removeAcl(aclPath);
        assertFalse(AccessController.aclExists(aclPath));
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

    /**
     * tests if DDC and DOC entries are copied.
     * @throws Exception if error
     */
    @Test
    public void testGetDDCEntries() throws Exception {
        String ddcAclName = "/dcctest";
        AccessControlListIF ddcAcl = AccessController.getAcl(ddcAclName);

        List<HashMap<String, String>>  ddcEntries = ddcAcl.getDOCAndDCCEntries();

        assertTrue(ddcEntries.size() == 6);

    }

    /**
     * tests if ACL is created correctly.
     * @throws Exception if fail
     */
    @Test
    public void testAddDDC() throws Exception {
        String prj1 = "/dcctest/prjA";

        //PM adds a project
        AccessController.addAcl(prj1, "pm1", "ProjectA", true);

        //check if entries are correctly copied:
        AccessControlListIF prj1Acl = AccessController.getAcl(prj1);

        //this ACL has 6 DOC+DDC entries
        assertTrue(prj1Acl.getDOCAndDCCEntries().size() == 6);

        //owner gets d,c, x by DDC and DOC
        assertTrue(prj1Acl.checkPermission("pm1", "c"));
        assertTrue(prj1Acl.checkPermission("pm1", "x"));

        //not owner
        assertTrue(!prj1Acl.checkPermission("pm2", "c"));

        //authenticated has 'x'
        assertTrue(prj1Acl.checkPermission("pm2", "x"));

        assertTrue(!prj1Acl.checkPermission("prj_user1", "c"));
        assertTrue(!prj1Acl.checkPermission("john", "c"));

        //PM's get i from DDC
        assertTrue("PM2 must have permission 'i'", prj1Acl.checkPermission("pm2", "i"));

        //pm1 is owner and user permissions override group permissions
        assertTrue("PM1 must not have permission 'i'", !prj1Acl.checkPermission("pm1", "i"));

        assertTrue(!prj1Acl.checkPermission("john", "i"));
        assertTrue(!prj1Acl.checkPermission("prj_user3", "i"));

        //PR users get i and v
        assertTrue(prj1Acl.checkPermission("prj_user3", "u"));
        assertTrue(prj1Acl.checkPermission("prj_user3", "v"));

        //authenticated get v, x
        assertTrue(prj1Acl.checkPermission("andrei", "v"));
        assertTrue(prj1Acl.checkPermission("andrei", "x"));
        assertTrue(!prj1Acl.checkPermission("andrei", "u"));
        // Clean up
        AccessController.removeAcl(prj1);
        assertFalse(AccessController.aclExists(prj1));
    }

    /**
     * Tests adding ACL to lower level.
     * @throws Exception if error happens
     */
    @Test
    public void testAddSubProjects() throws Exception {
        String prj1 = "/dcctest/prjB";

        String prj11 = "/dcctest/prjB/subA1";
        String prj12 = "/dcctest/prjB/subA2";
        String prj1File1 = "/dcctest/prjB/file1";
        String prj1File2 = "/dcctest/prjB/file2";


        //PM adds a project
        AccessController.addAcl(prj1, "pm1", "ProjectA", true);

        //add sub projects of 1
        AccessController.addAcl(prj11, "pm1", "ProjectA sub 1", true);
        AccessController.addAcl(prj12, "pm2", "ProjectA sub 2", true);

        AccessController.addAcl(prj1File1, "james", "ProjectA sub1 file 1");
        AccessController.addAcl(prj1File2, "prj_user2", "ProjectA sub1 file 2");

        AccessControlListIF prj11Acl = AccessController.getAcl(prj11);
        AccessControlListIF prj1File1Acl = AccessController.getAcl(prj1File1);
        AccessControlListIF prj1File2Acl = AccessController.getAcl(prj1File2);

        assertTrue("DDC entires not copied to sub level  ", prj11Acl.getDOCAndDCCEntries().size() == 6);
        assertTrue("DDC entires must not be copied if file: ",  prj1File1Acl.getDOCAndDCCEntries().size() == 0);

        //pm1 created sub1 - has to get c as owner
        assertTrue("sub1 owner not got C", prj11Acl.checkPermission("pm1", "c"));
        assertTrue("sub1 not owner got C", !prj11Acl.checkPermission("pm2", "c"));

        assertTrue("sub1 file owner not got D", prj1File1Acl.checkPermission("james", "d"));

        assertTrue("sub1 file 2 owner not got D", prj1File2Acl.checkPermission("prj_user2", "d"));
        assertTrue("sub1 file 2 not owner got D", !prj1File2Acl.checkPermission("prj_user3", "d"));

        assertTrue("sub1 file not owner got D", !prj1File1Acl.checkPermission("prj_user3", "d"));
        assertTrue("sub1 file anonymous got D", !prj1File1Acl.checkPermission(null, "d"));

        // tests on adding acl to the second sub-level.
        String prj12lA = "/dcctest/prjB/subA2/level2A";
        String prj12lB = "/dcctest/prjB/subA2/level2B";

        AccessController.addAcl(prj12lA, "pm1", "ProjectB level2 A", true);
        AccessController.addAcl(prj12lB, "pm2", "ProjectB level2 B", true);

        AccessControlListIF prj12lAAcl = AccessController.getAcl(prj12lA);
        AccessControlListIF prj12lBAcl = AccessController.getAcl(prj12lB);

        assertTrue("DDC entires not copied to 2nd sub level  ", prj12lAAcl.getDOCAndDCCEntries().size() == 6);
        assertTrue("DDC entires not copied to 2nd sub level  ", prj12lBAcl.getDOCAndDCCEntries().size() == 6);

        assertTrue("sub1 owner not got C", prj12lAAcl.checkPermission("pm1", "c"));
        assertTrue("sub1 not owner got C", !prj12lAAcl.checkPermission("pm2", "c"));

        assertTrue("sub1 not got i", prj12lAAcl.checkPermission("pm2", "i"));
        assertTrue("sub1 not got i", prj12lBAcl.checkPermission("pm1", "i"));

        assertTrue("sub1 not got d", prj12lBAcl.checkPermission("pm2", "d"));

        // Clean up
        AccessController.removeAcl(prj12lA);
        AccessController.removeAcl(prj12lB);
        AccessController.removeAcl(prj11);
        AccessController.removeAcl(prj12);
        AccessController.removeAcl(prj1File1);
        AccessController.removeAcl(prj1File2);
        AccessController.removeAcl(prj1);
        assertFalse(AccessController.aclExists(prj1));
    }

    /**
     * test ACLs in folder system.
     * @throws Exception if error
     */
    @Test
    public void testOwnerDDCFolder() throws Exception {
        String prjName = "/eeaprojects/toolx";
        AccessController.addAcl(prjName, "john", "Tool X", true);

        AccessControlListIF acl = AccessController.getAcl(prjName);

        //6 entries copied, 3 of them is DOC and DDC
        assertTrue(acl.getEntryRows().size() == 6);
        assertTrue(acl.getDOCAndDCCEntries().size()  == 4);

        //auth must have v and x
        assertTrue(acl.checkPermission("another", "x"));
        assertTrue(acl.checkPermission("anotherA", "v"));
        assertTrue(!acl.checkPermission("another", "d"));

        //owner must have w,d,c,x
        assertTrue(acl.checkPermission("john", "c"));
        assertTrue(acl.checkPermission("john", "u"));
        assertTrue(acl.checkPermission("john", "x"));
        assertTrue(acl.checkPermission("john", "v"));

        // Clean up
        AccessController.removeAcl(prjName);
        assertFalse(AccessController.aclExists(prjName));
    }

    /**
     * create an ACL that does not have folder system all permissions must remain sam but DDC and DOC are not copied.
     * @throws Exception if error
     */
    @Test
    public void testOwnerDDCNoFolders() throws Exception {
        String prjName = "/eeaprojects/tooly";
        AccessController.addAcl(prjName, "john", "Tool Y", false);

        AccessControlListIF acl = AccessController.getAcl(prjName);

        //6 entries copied, 3 of them is DOC and DDC
        assertTrue(acl.getEntryRows().size() == 2);
        assertTrue(acl.getDOCAndDCCEntries().size()  == 0);

        //auth must have v and x
        assertTrue(acl.checkPermission("another", "x"));
        assertTrue(acl.checkPermission("anotherA", "v"));
        assertTrue(!acl.checkPermission("another", "d"));

        //owner must have w,d,c,x
        assertTrue(acl.checkPermission("john", "c"));
        assertTrue(acl.checkPermission("john", "u"));
        assertTrue(acl.checkPermission("john", "x"));
        assertTrue(acl.checkPermission("john", "v"));

        // Clean up
        AccessController.removeAcl(prjName);
        assertFalse(AccessController.aclExists(prjName));
    }

    /**
     * tests if ACL gets DCC entry if no DCC entries.
     * @throws Exception if fail
     */
    @Test
    public void testAddDefaultDCC() throws Exception {
        String folder = "/whatever/folder7";

        //PM adds a project
        AccessController.addAcl(folder, "folder7", "testFolder", true);

        //check if entries are correctly copied:
        AccessControlListIF folderAcl = AccessController.getAcl(folder);

        //this ACL has 2 entries + 2 DOC/DCC entries
        assertTrue(folderAcl.getEntryRows().size() == 4);
        assertTrue(folderAcl.getDOCAndDCCEntries().size() == 2);

        // Clean up
        AccessController.removeAcl(folder);
        assertFalse(AccessController.aclExists(folder));
    }

    @Test
    public void renameTestHappyPath() throws Exception {
        String object1 = "/whatever/object1";
        String newObject = "/whatever/newname";

        AccessController.addAcl(object1, "enriko", "Description of my object");
        assertTrue(AccessController.aclExists(object1));
        assertFalse(AccessController.aclExists(newObject));

        AccessController.renameAcl(object1, newObject);
        assertFalse(AccessController.aclExists(object1));
        assertTrue(AccessController.aclExists(newObject));
        
        // Clean up
        AccessController.removeAcl(newObject);
        assertFalse(AccessController.aclExists(newObject));
    }

    @Test
    public void renameTestMustFail() throws Exception {
        String object1 = "/whatever/object1";
        String newObject = "/somethingelse/newname";

        AccessController.addAcl(object1, "enriko", "Description of my object");
        assertTrue(AccessController.aclExists(object1));
        assertFalse(AccessController.aclExists(newObject));

        thrown.expect(SignOnException.class);
        try {
            AccessController.renameAcl(object1, newObject);
        } finally {
            assertTrue(AccessController.aclExists(object1));
            assertFalse(AccessController.aclExists(newObject));
            
            // Clean up
            AccessController.removeAcl(object1);
            assertFalse(AccessController.aclExists(object1));
        }
    }
}
