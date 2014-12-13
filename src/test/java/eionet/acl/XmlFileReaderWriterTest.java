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
import java.security.Principal;
import java.security.acl.Group;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Test XML reader.
 *
 * @author Søren Roug
 */
public class XmlFileReaderWriterTest {

    @Test
    public void checkGroupMembership() throws SignOnException {
        String groupsFile = "target/test-classes/seed-groups.xml";
        HashMap<String, Principal> users = new HashMap<String, Principal>();
        HashMap<String, Group> groups = new HashMap<String, Group>();

        XmlFileReaderWriter.readGroups(groupsFile, groups, users);
        assertTrue(groups.containsKey("rod_admin"));
        assertTrue(groups.containsKey("rod_user"));
        assertFalse(groups.containsKey("nosuchgroup"));
        assertTrue(users.containsKey("desmepet"));
        Principal desmetPrin = users.get("desmepet");
        Group rodUserGroup = groups.get("rod_user");
        assertTrue(rodUserGroup.isMember(desmetPrin));
        Principal kasperenPrin = users.get("kasperen");
        assertFalse(rodUserGroup.isMember(kasperenPrin));
    }

}

