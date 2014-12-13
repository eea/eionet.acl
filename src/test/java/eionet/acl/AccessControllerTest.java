/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is ACL
 *
 * The Initial Owner of the Original Code is European Environment
 * Agency.  Portions created by TietoEnator Estonia are
 * Copyright (C) 2007-2014 European Environment Agency. All
 * Rights Reserved.
 *
 * Contributor(s):
 * Jaanus Heinlaid
 * Søren Roug, EEA
 */

package eionet.acl;

import java.util.HashMap;
import java.util.Vector;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Test permissions logic.
 *
 * @author Jaanus Heinlaid
 */
public class AccessControllerTest extends ACLDatabaseTestCase {

    /**
     * Enriko is in no group and has no "user" line, so he gets "authenticated".
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadEnriko() throws SignOnException {
        
        // test AccessController.getPermissions()
        String permissions = AccessController.getPermissions("enriko");
        assertTrue("'x' permission in root ACL is granted", permissions.indexOf(",/:x,") >= 0);
        
        // test AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("enriko");
        assertTrue("'x' permission in root ACL is granted", permsVector.indexOf("x") >= 0);
    }

    /**
     * The anonymous user, or is the syntax getPermissions(null)?
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadAnonymous() throws SignOnException {
        
        // test AccessController.getPermissions()
        String permissions = AccessController.getPermissions("anonymous");
        assertTrue("'v' permission in root ACL is granted", permissions.indexOf(",/:v,") >= 0);

        // test AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("anonymous");
        assertTrue("'v' permission in root ACL is granted", permsVector.indexOf("v") >= 0);
    }

    /**
     * Risto is in the "app_user" group.
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadRisto() throws SignOnException {

        // test AccessController.getPermissions()
        String permissions = AccessController.getPermissions("risto");
        assertTrue("'v' permission in root ACL is granted", permissions.indexOf(",/:v,") >= 0);

        // test AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("risto");
        assertTrue("'v' permission in root ACL is granted", permsVector.indexOf("v") >= 0);
    }

    /**
     * Anni is in both "inserters" and "deleters" groups and must have "i" and "d" permissions.
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadAnni() throws SignOnException {

        // test AccessController.getPermissions()
        String permissions = AccessController.getPermissions("anni");
        assertTrue("'d' permission in root ACL is granted", permissions.indexOf(",/:d,") >= 0);
        assertTrue("'i' permission in root ACL is granted", permissions.indexOf(",/:i,") >= 0);

        // test AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("anni");
        assertTrue("'d' permission in root ACL is granted", permsVector.indexOf("d") >= 0);
        assertTrue("'i' permission in root ACL is granted", permsVector.indexOf("i") >= 0);
    }

    /**
     * Identical to test_Jaanus2, but "jaanus1" comes before "app_admin" group.
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadJaanus1() throws SignOnException {
        
        String permissions = AccessController.getPermissions("jaanus1");

        // assert permissions in root ACL
        assertTrue("'d' permission in root ACL is granted", permissions.indexOf(",/:d,") >= 0);     
        assertFalse("'v' permission must not be present in root ACL", permissions.indexOf(",/:v,") >= 0);
        assertFalse("'i' permission must not be present in root ACL", permissions.indexOf(",/:i,") >= 0);
        
        // assert permissions in /localgroups ACL
        assertTrue("'v' permission in /localgroups ACL is granted", permissions.indexOf(",/localgroups:v,") >= 0);
        assertFalse("'u' permission must not be present in /localgroups ACL", permissions.indexOf(",/:u,") >= 0);
        
        // now do all the same, but this time using AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("jaanus1");
        assertTrue("'d' permission in root ACL is granted", permsVector.indexOf("d") >= 0);     
        assertFalse("'v' permission must not be present in root ACL", permsVector.indexOf("v") >= 0);
        assertFalse("'i' permission must not be present in root ACL", permsVector.indexOf("i") >= 0);
        assertFalse("'u' permission must not be present in /localgroups ACL", permsVector.indexOf("u") >= 0);
        permsVector = AccessController.getAcl("/localgroups").getPermissions("jaanus1");
        assertTrue("'v' permission in /localgroups ACL is granted", permsVector.indexOf("v") >= 0);
    }

    /**
     * Identical to test_Jaanus1, but "jaanus2" comes after "app_admin" group.
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadJaanus2() throws SignOnException {
        
        String permissions = AccessController.getPermissions("jaanus2");
        
        assertTrue("'d' permission in root ACL is granted", permissions.indexOf(",/:d,") >= 0);
        assertFalse("'v' permission must not be present in root ACL", permissions.indexOf(",/:v,") >= 0);
        assertFalse("'i' permission must not be present in root ACL", permissions.indexOf(",/:i,") >= 0);

        // now do all the same, but this time using AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("jaanus2");
        assertTrue("'d' permission in root ACL is granted", permsVector.indexOf("d") >= 0);
        assertFalse("'v' permission must not be present in root ACL", permsVector.indexOf("v") >= 0);
        assertFalse("'i' permission must not be present in root ACL", permsVector.indexOf("i") >= 0);

    }

    /**
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadRoug() throws SignOnException {
        
        String permissions = AccessController.getPermissions("roug");
        assertTrue("'v' permission in root ACL is granted", permissions.indexOf(",/:v,") >= 0);
        assertTrue("'c' permission in root ACL is granted", permissions.indexOf(",/:c,") >= 0);
        assertFalse("'x' permission must not be present in root ACL", permissions.indexOf(",/:x,") >= 0);
        
        // now do all the same, but this time using AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("roug");
        assertTrue("'v' permission in root ACL is granted", permsVector.indexOf("v") >= 0);
        assertTrue("'c' permission in root ACL is granted", permsVector.indexOf("c") >= 0);
        assertFalse("'x' permission must not be present in root ACL", permsVector.indexOf("x") >= 0);
    }

    /**
     * Ander has no permissions, but is member of app_admin group.
     * 
     * @throws SignOnException
     */
    @Test
    public void testReadAnder() throws SignOnException {
        
        String permissions = AccessController.getPermissions("ander");
        assertFalse("'v' permission must not be present in root ACL", permissions.indexOf(",/:v,") >= 0);
        assertFalse("'x' permission must not be present in root ACL", permissions.indexOf(",/:x,") >= 0);

        // now do all the same, but this time using AccessController.getAcl().getPermissions()
        Vector permsVector = AccessController.getAcl("/").getPermissions("ander");
        assertFalse("'v' permission must not be present in root ACL", permsVector.indexOf("v") >= 0);
        assertFalse("'x' permission must not be present in root ACL", permsVector.indexOf("x") >= 0);
    }
    
    /**
     * 
     *
     */
    @Test
    public void test_getAcls() {
        
        try {
            HashMap acls = AccessController.getAcls();
            assertNotNull("AccessController.getAcls() must not return null here", acls);
            assertTrue("expected AccessController.getAcls() to contain the key \"/\"", acls.containsKey("/"));
            assertTrue("expected AccessController.getAcls() to contain the key \"/whatever\"", acls.containsKey("/whatever"));
            assertTrue("expected AccessController.getAcls() to contain the key \"/localgroups\"", acls.containsKey("/localgroups"));
        } catch (SignOnException e) {
            fail("Was not expecting this exception: " + e.toString());
        }
    }
}

