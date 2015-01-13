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
 * The Original Code is "EINRC-6 / AIT project".
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

import java.security.Principal;
import java.security.acl.Group;
import java.security.acl.Permission;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;


/**
 * This class mixes the capabilities of two classes to support
 * the legacy.
 */
class PersistenceMix implements Persistence {

    /** logger instance. */
    private static final Logger LOGGER = Logger.getLogger(PersistenceMix.class);

    private PersistenceFile fileModule;
    private PersistenceDB dbModule;


    public PersistenceMix(Hashtable props) {
        fileModule = new PersistenceFile(props);
        //TODO: Only call dbModule if there is a property for it.
        try {
            dbModule = new PersistenceDB(props);
        } catch (DbNotSupportedException e) {
            dbModule = null;
        }
    }

    /**
     * Read permissions from the files.
     *
     * @throws SignOnException if reading fails
     */
    @Override
    public void readPermissions(HashMap<String, Permission> permissions, Hashtable<String, String> prmDescrs) throws SignOnException {
        fileModule.readPermissions(permissions, prmDescrs);
    }

    /**
     * Read local groups from the files.
     *
     * @throws SignOnException if reading fails
     */
    @Override
    public void readGroups(HashMap<String, Group> groups, HashMap<String, Principal> users) throws SQLException, SignOnException {
        fileModule.readGroups(groups, users);
    }

    /**
     * Write local groups to file.
     */
    @Override
    public void writeGroups(Hashtable<String, Group> groups) throws SignOnException {
        fileModule.writeGroups(groups);
    }

    /**
     * Read the ACL files from the designated folder.
     *
     * @param acls - a hashmap to be filled by the method.
     */
    @Override
    public void initAcls(HashMap<String, AccessControlListIF> acls) throws SQLException, SignOnException {
        fileModule.initAcls(acls);
        if (dbModule != null) {
            dbModule.initAcls(acls);
        }
    }

    @Override
    public void addAcl(String aclPath, String owner, String description, boolean isFolder)
                throws SQLException, SignOnException {
        if (dbModule != null) {
            dbModule.addAcl(aclPath, owner, description, isFolder);
        } else {
            throw new SignOnException("Method is not supported");
        }
    }

    @Override
    public void addAcl(String aclPath, String owner, String description) throws SQLException, SignOnException {
        if (dbModule != null) {
            dbModule.addAcl(aclPath, owner, description);
        } else {
            throw new SignOnException("Method is not supported");
        }
    }

    /**
     * Write ACL. This method will never be called as the writeAcl() is called
     * from the ACL, and it knows what persistence module it works under.
     */
    @Override
    public void writeAcl(String aclName, Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
        dbModule.writeAcl(aclName, aclAttrs, aclEntries);
    }

    @Override
    public void removeAcl(String aclPath) throws SQLException, SignOnException {
        if (dbModule != null) {
            dbModule.removeAcl(aclPath);
        } else {
            throw new SignOnException("Method is not supported");
        }
    }

    @Override
    public void renameAcl(String currentAclPath, String newAclPath) throws SQLException, SignOnException {
        if (dbModule != null) {
            dbModule.renameAcl(currentAclPath, newAclPath);
        } else {
            throw new SignOnException("Method is not supported");
        }
    }

}
