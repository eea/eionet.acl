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
 * The Original Code is ACL.
 *
 * The Initial Developer of the Original Code is TietoEnator.
 * The Original Code code was developed for the European
 * Environment Agency (EEA) under the IDA/EINRC framework contract.
 *
 * Copyright (C) 2000-2014 by European Environment Agency.  All
 * Rights Reserved.
 *
 * Original Code: Kaido Laine (TietoEnator)
 */

package eionet.acl;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Vector;

import eionet.acl.impl.PermissionImpl;

/**
 * Access point to the API for ACL operations.
 */
public final class AccessController {

    /** ACLs. */
    private static HashMap acls;

    /** System properties. */
    private static ResourceBundle props;

    /** Module of DB operations. */
    private static DbModuleIF dbModule;

    /** ACL files reader. */
    private static AclFileReader fileReader;

    /** File name for local groups. */
    static String localgroupsFileName;
    /** File name for permissions. */
    static String permissionsFileName;
    /** Folder where ACL files reside. */
    static String aclsFolderName;

    /** Permission to indicate ownership for the ACL. */
    static String ownerPrm = "";

    /** Reserved username for entries of anonymous access. */
    static String anonymousEntry = "";
    /** Reserved username for entries for authenticated users. */
    static String authEntry = "";

    /** HashMap for groups. */
    static HashMap groups;
    /** HashMap for user entries. */
    static HashMap users;
    /** HashMap for permissions. */
    static HashMap permissions;
    /** HashMap for permission descriptions. */
    static Hashtable prmDescrs;

    /** Default permissions for ACLs no DOC and DCC defined. */
    static String defaultDocAndDccPermissions = "v,i,u,d,c";

    /**
     * Indicates if database connection has been lost.
     * if it is in error ACLs are re-ninitialized
     */
    static boolean dbInError = false;

    /**
     *
     */
    static {
        fileReader = new AclFileReader();
    }

    /**
     * Prevent direct initialization.
     */
    private AccessController() {

    }

    /**
     * Returns all ACLs in the AccessController.
     *
     * @return HashMap of ACLs
     * @throws SignOnException if reading fails
     */
    public static HashMap getAcls() throws SignOnException {

        //if DB is in error mode let's try to read ACLs each time until it succeeds
        if (dbInError) {
            reset();
        }

        if (acls == null) {
            initAcls();
        }
        return acls;
    }

    /**
     * Returns ACL with the given name.
     * @param name full ACL path
     * @return ACL
     * @throws SignOnException if the ACL does not exist
     */
    public static AccessControlListIF getAcl(String name) throws SignOnException {
        if (acls == null) {
            initAcls();
        }

        if (acls.containsKey(name)) {
            return (AccessControlListIF) acls.get(name);
        } else {
            throw new AclNotFoundException("Could not find ACL by the name of " + name);
        }

    }

    /**
     * Reads ACL entries from the files and database if database supported.
     * @throws SignOnException if error in reading
     */
    private static void initAcls() throws SignOnException {

        try {
            readProperties();

            users = new HashMap();
            groups = new HashMap();
            permissions = new HashMap();
            prmDescrs = new Hashtable();

            readGroups();
            readPermissions();

            // read acl files
            File[] aclFiles = fileReader.getAclFiles(aclsFolderName);
            acls = new HashMap();
            for (int i = 0; i < aclFiles.length; i++) {
                String name = fileReader.getAclName(aclFiles[i]);
                AccessControlListIF acl = new AccessControlList(aclFiles[i]);

                name = name.replace('_', '/');

                acls.put(name, acl);
            }

            //returns null if DB is not supported, no exception thrown
            DbModuleIF db = getDbModule();

            // DB ACLS may be not supported then they are just ignored
            if (db != null) {
                db.initAcls(acls);
            }
        } catch (Exception e) {
            reset(); // otherwise some acls might remain successfylly in session, others not, causing confusion in user
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Error reading ACLs " + e);
        }
    }

    /**
     * Resets ACLs.
     */
    static void reset() {
        acls = null;
    }

    /**
     * Instance of uit.properties file.
     * @return REsourceBundle of the properties
     * @throws SignOnException if no file found.
     */

    static ResourceBundle getProperties() throws SignOnException {
        if (props == null)
            try {
                props = ResourceBundle.getBundle("uit");
            } catch (MissingResourceException mre) {
                throw new SignOnException("Properties file uit.properties is not existing in the classpath");
            }
        return props;
    }

    /**
     * Reads values from the property file.
     * @throws SignOnException if property is missing.
     */
    private static void readProperties() throws SignOnException {

        props = getProperties();

        // read mandatory properties
        try {
            permissionsFileName = props.getString("application.permissions.file");
            localgroupsFileName = props.getString("application.localgroups.file");

            aclsFolderName = props.getString("application.acl.folder");
            ownerPrm = props.getString("acl.owner.permission");
            // pre-defined entry name for anonymous access
            anonymousEntry = props.getString("acl.anonymous.access");

            // pre-defined entry name for authenticated access
            authEntry = props.getString("acl.authenticated.access");

            if (props.containsKey("acl.defaultdoc.permissions")) {
                defaultDocAndDccPermissions = props.getString("acl.defaultdoc.permissions");
            }

        } catch (MissingResourceException mre) {
            throw new SignOnException("Property is missing: " + mre.toString());
        }

        if (ownerPrm.length() > 1) {
            throw new SignOnException("Permission must be one letter");
        }
    }

    /**
     * Local groups of the system.
     * @return hash with groups
     * @throws SignOnException if reading fails
     */
    static Hashtable getGroups() throws SignOnException {

        Hashtable h = new Hashtable();
        for (Iterator i = groups.keySet().iterator(); i.hasNext();) {
            Group group = (Group) groups.get(i.next());
            Vector members = getGroupMembers(group);

            h.put(group.getName(), members);
        }

        return h;
    }

    /**
     * Members of the group.
     * @param g local group
     * @return Array of members
     */
    private static Vector getGroupMembers(Group g) {
        Enumeration members = g.members();
        Vector m = new Vector();
        while (members.hasMoreElements()) {
            m.add(((Principal) members.nextElement()).getName());
        }
        return m;
    }

    /**
     * Returns permissions of the user in all ACls.
     * Format: ACLName:p1,ACLName:p2,AclName2:p1,
     * @param user username
     * @return permissions of user in required format
     * @throws SignOnException if reading fails
     */
    public static String getPermissions(String user) throws SignOnException {

        if (acls == null) {
            initAcls();
        }

        StringBuffer s = new StringBuffer();

        for (Iterator i = acls.keySet().iterator(); i.hasNext();) {
            String aclName = (String) i.next();
            Vector ePerms = ((AccessControlListIF) acls.get(aclName)).getPermissions(user);
            s.append(parsePerms(aclName, ePerms));
        }

        return s.toString();
    }

    /**
     * Parse permissions in an array and composes CSV format.
     * @param aclName full ACL path
     * @param aclPerms Array of ACL permissions
     * @return string in format aclName:perm1,perm2,...,permN
     */
    private static String parsePerms(String aclName, Vector aclPerms) {
        StringBuffer s = new StringBuffer();

        //nb it is fine that it begins and ends with a comma
        for (int i = 0; i < aclPerms.size(); i++) {
            s.append(",").append(aclName).append(":").append((String) aclPerms.elementAt(i)).append(",");
        }

        return s.toString();
    }


    /**
     * Read groups from an XML file and set to the controller.
     * @param groups hash of the groups
     * @throws SignOnException if file writing fails
     */
    static void setGroups(Hashtable groups) throws SignOnException {
        XmlFileReaderWriter.writeGroups(localgroupsFileName, groups);
    }


    /**
     * HARD-CODED permissions for ACL "localgroups".
     * @return permissions in a hash in required format
     */
    static HashMap groupPermissions() {
        HashMap gPerms = new HashMap();
        gPerms.put("v", new PermissionImpl("v"));
        gPerms.put("c", new PermissionImpl("c"));
        gPerms.put("u", new PermissionImpl("u"));

        return gPerms;

    }

    /**
     * Returns the DB module for DB operations.
     * If DB connection is not supported in this application or error in DB  connection returns null
     * @return database module
     */
    static DbModuleIF getDbModule() {

        if (dbModule == null) {
            try {
                dbModule = new DbModule();
            } catch (DbNotSupportedException e) {
                return null;
            }
        }

        return dbModule;

    }

    /**
     * Adds a new ACL under the specified parent ACL.
     *
     * @param aclPath full acl Path - "/datasets/1234"
     * @param owner - the owner of the ACL - "jaanus"
     * @param description Descritpion of the ACL object - "Lakes"
     * @throws SignOnException if ACL exists or DB operation fails
     */
    public static void addAcl(String aclPath, String owner, String description) throws SignOnException {
        addAcl(aclPath, owner, description, false);
    }

    /**
     * Adds a new ACL.
     *
     * @param aclPath full ACL path "/datasets/1234"
     * @param owner owner username
     * @param description ACL description
     * @param hasSubFolders indicates if the created object can have subfolders
     * @throws SignOnException if ACL exists or DB operation fails
     */
    public static void addAcl(String aclPath, String owner, String description, boolean hasSubFolders) throws SignOnException {

        if (AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("ACL, named " + aclPath + " already exists.");
        }

        // ACLs can be added only to DB tables
        try {
            DbModuleIF dbm = getDbModule();
            // if acls in database are not supported, ignore
            if (dbm != null) {
                dbm.addAcl(aclPath, owner, description, hasSubFolders);
            }
        } catch (Exception e) {
            throw new SignOnException("DB operation failed : " + e.toString());
        }

        // reset the ACL container
        reset();
    }

    /**
     * Remove an ACL from the application.
     *
     * @param aclPath full ACL path
     * @throws SignOnException if no ACL or no DB support
     */
    public static void removeAcl(String aclPath) throws SignOnException {

        if (!AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("No such ACL: " + aclPath);
        }

        AccessControlListIF acl = AccessController.getAcl(aclPath);

        // if the ACL is not held in DB table this API function cannot be used
        if (acl.mechanism() != acl.DB) {
            throw new SignOnException("This ACL cannot be removed by this method.");
        }

        try {
            DbModuleIF dbm = getDbModule();
            // if acls in database are not supported, ignore
            if (dbm != null) {
                dbm.removeAcl(aclPath);
            }
        } catch (Exception e) {
            throw new SignOnException("DB operation failed : " + e.toString());
        }
        reset();
    }

    /**
     * Rename ACL.
     *
     * @param aclPath - existing ACL full path
     * @param newAclPath - new ACL full path
     * @throws SignOnException if renaming fails: no ACL or ACL with  the new name exists
     */
    public static void renameAcl(String aclPath, String newAclPath) throws SignOnException {

        if (!AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("No such ACL to be renamed: " + aclPath);
        }

        if (AccessController.getAcls().containsKey(newAclPath)) {
            throw new SignOnException("ACL with new name already exists: " + newAclPath);
        }
        AccessControlListIF acl = AccessController.getAcl(aclPath);

        // if the ACL is not held in DB table this API function cannot be used
        if (acl.mechanism() != acl.DB) {
            throw new SignOnException("This ACL cannot be renamed by this method.");
        }

        try {
            DbModuleIF dbm = getDbModule();
            // if acls in database are not supported, ignore
            if (dbm != null) {
                dbm.renameAcl(aclPath, newAclPath);
            }
        } catch (Exception e) {
            throw new SignOnException("DB operation failed : " + e.toString());
        }
        reset();
    }

    /**
     * Read local groups from the files.
     *
     * @throws SignOnException if reading fails
     */
    private static void readGroups() throws SignOnException {
        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(localgroupsFileName))
                XmlFileReaderWriter.readGroups(localgroupsFileName, groups, users);
            else
                fileReader.readGroups(localgroupsFileName, groups, users);
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException)
                throw new SignOnException(e, "No such file: " + localgroupsFileName);
            else
                throw new SignOnException(e, "I/O error reading file: " + localgroupsFileName);
        }
    }

    /**
     * Read permissions from the files.
     *
     * @throws SignOnException if reading fails
     */
    private static void readPermissions() throws SignOnException {
        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(permissionsFileName))
                XmlFileReaderWriter.readPermissions(permissionsFileName, permissions, prmDescrs);
            else
                fileReader.readPermissions(permissionsFileName, permissions, prmDescrs);
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException)
                throw new SignOnException(e, "No such file: " + localgroupsFileName);
            else
                throw new SignOnException(e, "I/O error reading file: " + localgroupsFileName);
        }
    }

    /**
     * Check if an ACL with given name exists.
     *
     * @param aclName ACL name
     * @return true if ACL exists
     * @throws SignOnException if reading ACLs does not succeed
     */
    public static boolean aclExists(String aclName) throws SignOnException {
        return getAcls().containsKey(aclName);
    }
}
