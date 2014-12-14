/**
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

/**
 * Interface for Access Control Lists.
 *
 * @author Jaanus Heinlaid
 *
 */
public interface AccessControlListIF {

    /** ACL comes from text file. */
    public static final int TEXT_FILE = 1;
    /** ACL comes from database. */
    public static final int DB = 2;

    /**
     * Check, if user has this permission.
     */
    public boolean checkPermission(String user, String permission) throws SignOnException;

    /**
     * Return array of permissions of user.
     */
    public Vector getPermissions(String user) throws SignOnException;

    /**
     * Return ACL entries in ARRAY.
     * [localgroup|circarole|user]:name:p1,p2,...,pN
     */
    public Vector getEntryRows( ) throws SignOnException;

    /**
     * Returns DOC and DCC entries of the ACL.
     *
     * @return list of entries
     * @throws SignOnException if call fails
     */
    List<HashMap<String, String>> getDOCAndDCCEntries()  throws SignOnException;

    /**
     * Returns a code specifying if the ACL comes from file or database.
     *
     * @return one of AccessControlListIF.TEXT_FILE or AccessControlListIF.DB
     */
    public int mechanism();

    /**
     * Set ACL entries.
     *
     * @param aclEntries
     * @throws SignOnException
     */
    public void setAclEntries(Vector aclEntries) throws SignOnException;

    /**
     * Set ACL.
     *
     * @param aclAttrs
     * @param aclEntries
     * @throws SignOnException
     */
    public void setAcl(Map aclAttrs, List aclEntries) throws SignOnException;

    /**
     * Check if the user is the owner of the object.
     *
     * @param user
     * @return true if the user is the owner of the object.
     * @throws SignOnException
     */
    public boolean isOwner(String user) throws SignOnException;

    /**
     * Get the name (a.k.a. path) of the ACL.
     * @return the path
     */
    public String getName();

    /**
     * Get the human readable description of the ACL.
     * @return the description
     */
    public String getDescription();
}
