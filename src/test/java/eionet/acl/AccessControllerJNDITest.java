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

import eu.europa.eionet.propertyplaceholderresolver.ConfigurationDefinitionProviderImpl;
import eu.europa.eionet.propertyplaceholderresolver.ConfigurationPropertyResolver;
import eu.europa.eionet.propertyplaceholderresolver.ConfigurationPropertyResolverImpl;
import java.util.HashMap;
import java.util.Vector;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

/**
 * Test permissions logic where AccessController is initialised via JNDI.
 *
 * @author Søren Roug
 */
public class AccessControllerJNDITest extends ACLDatabaseTestCase {

    @Before
    public void setUp() throws Exception {
        ConfigurationPropertyResolver propertyResolver = new ConfigurationPropertyResolverImpl(new ConfigurationDefinitionProviderImpl("acl.properties"));
        AccessController.initAccessController(propertyResolver);
    }

    /**
     * Test that the anonymous user has 'v' permission and not 'c' permission.
     */
    @Test
    public void anonymousOnRoot() throws SignOnException {
        assertTrue(AccessController.hasPermission(null, "/", "v"));
        assertFalse(AccessController.hasPermission(null, "/", "x"));
    }

    /**
     * Test that enriko has 'x' permission and not 'c' permission.
     * Enriko is in no group and has no "user" line, so he gets "authenticated".
     */
    @Test
    public void enrikoOnRoot() throws SignOnException {
        assertTrue(AccessController.hasPermission("enriko", "/", "x"));
        assertFalse(AccessController.hasPermission("enriko", "/", "c"));
    }

}

