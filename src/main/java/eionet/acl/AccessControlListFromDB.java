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
 * The Original Code is "EINRC-5 / UIT project".
 *
 * The Initial Developer of the Original Code is TietoEnator.
 * The Original Code code was developed for the European
 * Environment Agency (EEA) under the IDA/EINRC framework contract.
 *
 * Copyright (C) 2000-2002 by European Environment Agency.  All
 * Rights Reserved.
 *
 * Original Code: Kaido Laine (TietoEnator)
 */


package eionet.acl;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Acl;
import java.security.acl.AclEntry;
import java.security.acl.Group;
import java.security.acl.NotOwnerException;
import java.security.acl.Permission;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.log4j.Logger;

import eionet.acl.impl.AclEntryImpl;
import eionet.acl.impl.AclImpl;
import eionet.acl.impl.GroupImpl;
import eionet.acl.impl.PrincipalImpl;



/**
 * ACL implementation. Works on the ACL object, and can read/write them, but
 * does not create new ACLs.
 */
class AccessControlListFromDB extends AccessControlList {

    private static final Logger LOGGER = Logger.getLogger(AccessControlListFromDB.class);

    private DbModuleIF dbPool;


    /**
     * Constructor if the ACL is initialised based on DB table rows.
     */
    AccessControlListFromDB(String name, String ownerName, String description, String[][] aclRows) throws SignOnException {
        super();

        setMechanism(DB);
        //we have to set a fake owner if there is no owner specified in the ACL
        if (ownerName == null || ownerName.equals(""))
            owner = new PrincipalImpl(name);
        else
            owner = new PrincipalImpl(ownerName);

        acl = new AclImpl(owner, name);
        this.description = description;
        this.name = name;

        readAclsFromDb(aclRows);

    }

    @Override
    public void setAcl(Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
        LOGGER.debug("setAcl()");
        try {
            if (dbPool == null) {
                try {
                    dbPool = new DbModule();
                } catch (DbNotSupportedException e) {
                    dbPool = null;
                }
            }

            if (dbPool != null) {
                LOGGER.debug("DbPool is not null going to save entries.");
                dbPool.writeAcl(name, aclAttrs, aclEntries);
            }
        } catch (SQLException e) {
            throw new SignOnException(e, "SQL error saving acl '" + name + "' into DB");
        }
    }

    @Override
    public void setAclEntries(Vector aclEntries) throws SignOnException {
        setAcl(null, aclEntries);
    }

    /**
     * Parse ACLS originating from Database.
     */
    private void readAclsFromDb(String[][] aclRows) throws SignOnException {
        ArrayList aRows = new ArrayList();
        //transform the String to an arraylist similar to text files
        for (int i = 0; i < aclRows.length; i++) {
            String type = aclRows[i][0];
            String eType = aclRows[i][1];
            String principal = aclRows[i][2];
            String perms = aclRows[i][3];

            if (eType.equals("authenticated") || eType.equals("anonymous")) {
                principal = eType;
                eType = "user";
            }
            if (eType.equals("owner"))
                eType = "user"; //not supported yet

            String aRow = eType + ":" + principal + ":" + perms;

            if (!type.equalsIgnoreCase("object")) {
                aRow = aRow + ":" + type;
            }


            aRows.add(aRow);
        }

        processAclRows(aRows);
    }

}
