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

import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * Database methods for dynamically editable ACLs.
 *
 * @author Kaido Laine
 */
public interface DbModuleIF {

    /**
     * Adds new ACL to the database.
     * @param aclPath full ACL path
     * @param owner owner username
     * @param description ACL description
     * @param isFolder indicates if it is a folder
     * @throws SQLException if SQL insert fail
     * @throws SignOnException if no permission
     */
    void addAcl(String aclPath, String owner, String description, boolean isFolder)
            throws SQLException, SignOnException;


    /**
     * Adds a new ACL to the database.
     *
     * @param aclPath full ACL path
     * @param owner username of the ACL owner
     * @param description ACL description
     * @throws SQLException if error in Database insert
     * @throws SignOnException if error in given aclPath or owner is null
     */
     void addAcl(String aclPath, String owner, String description) throws SQLException, SignOnException;

    /**
     * Removes the ACL from the database.
     * @param aclPath full ACL path
     * @throws SQLException if error in Database operations
     * @throws SignOnException if error in given aclPath
     */
    void removeAcl(String aclPath) throws SQLException, SignOnException;

    /**
     * Renames the ACL.
     * @param currentAclPath full ACL path to be renamed
     * @param newAclPath new ACL full path
     * @throws SQLException if error in Database operations
     * @throws SignOnException if error in the given ACL path formats
     */
    void renameAcl(String currentAclPath, String newAclPath) throws SQLException, SignOnException;

    /**
     * Reads ACLs from the DB into the HASH.
     * @param acls ACLs in Hash
     * @throws SQLException if error in reading from database
     * @throws SignOnException if error in ACL configuration etc
     */
    void initAcls(HashMap<String, AccessControlListIF> acls) throws SQLException, SignOnException;

    /**
     * Stores ACL in the DB table.
     *
     * @param aclName ACL path
     * @param aclAttrs - A map of attributes. The "description" is an attribute.
     * @param aclEntries list of ACL Entries
     * @throws SQLException if DB operation fails
     * @throws SignOnException if no such ACL with given name
     */
    void writeAcl(String aclName, Map<String, String> aclAttrs, List aclEntries) throws SQLException, SignOnException;
}
