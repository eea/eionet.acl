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
 * Contributor: Søren Roug
 */
package eionet.acl;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import eionet.acl.impl.PermissionImpl;
import java.lang.reflect.Constructor;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.apache.commons.lang.StringUtils.isBlank;

/**
 * Access point to the API for ACL operations.
 */
public final class AccessController {
    
    /**
     * AclProperties object to be provided at construction.
     */
    private static AclProperties aclProperties;

    /**
     * ACLs.
     */
    private static HashMap<String, AccessControlListIF> acls;

    /**
     * System properties.
     */
    private static String persistenceDriver;

    /**
     * File operations.
     */
    private static Persistence permStorage;

    /**
     * Permission to indicate ownership for the ACL.
     */
    static String ownerPrm = "";

    /**
     * Reserved username for entries of anonymous access.
     */
    static String anonymousEntry = "";
    /**
     * Reserved username for entries for authenticated users.
     */
    static String authEntry = "";

    /**
     * HashMap for groups.
     */
    static HashMap<String, Group> groups;
    /**
     * HashMap for user entries.
     */
    static HashMap<String, Principal> users;
    /**
     * HashMap for permissions.
     */
    static HashMap<String, Permission> permissions;
    /**
     * HashMap for permission descriptions.
     */
    static Hashtable<String, String> prmDescrs;

    /**
     * Default permissions for ACLs when no DOC and DCC defined.
     */
    static String defaultDocAndDccPermissions = "v,i,u,d,c";

    /**
     * Indicates if database connection has been lost. if it is in error ACLs
     * are re-initialized
     */
    static boolean dbInError = false;

    /**
     * Prevent direct initialization.
     */
    private AccessController() {
    }

    /**
     * An AclProperties object has to be supplied at instantiation
     *
     * @param aclProperties
     */
    public AccessController( AclProperties aclProperties) throws InvalidPropertiesException {
        this.initAccessController(aclProperties);
    }
        
        
    public static void initAccessController(AclProperties aclProperties) throws InvalidPropertiesException {
        AccessController.aclProperties = aclProperties;
        validateProperties ();
    }
    
    private static void validateProperties () throws InvalidPropertiesException {
        if ( aclProperties.getFileAclfolder() == null || aclProperties.getAnonymousAccess() == null ||
                aclProperties.getOwnerPermission() == null) {
            throw new InvalidPropertiesException("all mandatory properties must be provided at startup");
        }
    }

    /**
     * Returns all ACLs in the AccessController.
     *
     * @return HashMap of ACLs
     * @throws SignOnException if reading fails
     */
    public static HashMap<String, AccessControlListIF> getAcls() throws SignOnException {

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
     *
     * @param name full ACL path
     * @return ACL
     * @throws SignOnException if the ACL does not exist
     */
    public static AccessControlListIF getAcl(String name) throws SignOnException {
        if (acls == null) {
            initAcls();
        }

        if (acls.containsKey(name)) {
            return acls.get(name);
        } else {
            throw new AclNotFoundException("Could not find ACL by the name of " + name);
        }

    }

    /**
     * Reads ACL entries from the files and database if database supported.
     *
     * @throws SignOnException if error in reading
     */
    private static void initAcls() throws SignOnException {

        try {
            readProperties();

            users = new HashMap<String, Principal>();
            groups = new HashMap<String, Group>();
            permissions = new HashMap<String, Permission>();
            prmDescrs = new Hashtable<String, String>();
            acls = new HashMap<String, AccessControlListIF>();

            getPersistence();
            permStorage.readGroups(groups, users);
            permStorage.readPermissions(permissions, prmDescrs);
            permStorage.initAcls(acls);
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
     * Reads values from the property file.
     *
     * @throws SignOnException if property is missing.
     */
    private static void readProperties() throws SignOnException {

        // read mandatory properties
        ownerPrm = aclProperties.getOwnerPermission();
        // pre-defined entry name for anonymous access
        anonymousEntry = aclProperties.getAnonymousAccess();
        // pre-defined entry name for authenticated access
        authEntry = aclProperties.getAuthenticatedAccess();
        if ( ! isBlank( aclProperties.getDefaultdocPermissions() ) ) {
            defaultDocAndDccPermissions = aclProperties.getDefaultdocPermissions();
        }
        
        if ( isBlank( aclProperties.getPersistenceProvider() )  ) {
            persistenceDriver = "eionet.acl.PersistenceMix";
        }
        else {
            persistenceDriver = aclProperties.getPersistenceProvider();
        }

        if (ownerPrm.length() > 1) {
            throw new SignOnException("Permission must be one letter");
        }
    }

    private static void handleResolverException(Exception ex) throws SignOnException {
        Logger.getLogger(AccessController.class.getName()).log(Level.SEVERE, null, ex);
        throw new SignOnException(ex, ex.getMessage());
    }

    /**
     * Local groups of the system.
     *
     * @return hash with groups
     * @throws SignOnException if reading fails
     */
    static Hashtable<String, Vector<String>> getGroups() throws SignOnException {

        Hashtable<String, Vector<String>> h = new Hashtable<String, Vector<String>>();
        for (Iterator i = groups.keySet().iterator(); i.hasNext();) {
            Group group = (Group) groups.get(i.next());
            Vector<String> members = getGroupMembers(group);

            h.put(group.getName(), members);
        }

        return h;
    }

    /**
     * Members of the group.
     *
     * @param g local group
     * @return Array of members
     */
    private static Vector<String> getGroupMembers(Group g) {
        Enumeration<? extends Principal> members = g.members();
        Vector<String> m = new Vector<String>();
        while (members.hasMoreElements()) {
            m.add(((Principal) members.nextElement()).getName());
        }
        return m;
    }

    /**
     * Method to check if the user has the requested permission. If the user
     * name is null or empty then the user is not authenticated.
     *
     * @param userName - name of the account
     * @param aclPath - like "/" or "/whatever"
     * @param permissionFlag - Permission flag - like "r".
     * @return true if the user has the requested permission.
     * @throws SignOnException if reading fails
     */
    public static boolean hasPermission(String userName, String aclPath, String permissionFlag) throws SignOnException {
        AccessControlListIF acl = getAcl(aclPath);
        return acl.checkPermission(userName, permissionFlag);
    }

    /**
     * Method to check if the user has the requested permission. If the
     * principal is null then the user is not authenticated.
     *
     * @param principal - User object that implements the UserPrincipal
     * interface.
     * @param aclPath - like "/" or "/whatever"
     * @param permissionFlag - Permission flag - like "r".
     * @return true if the user has the requested permission.
     * @throws SignOnException if reading fails
     */
    /*
     public static boolean hasPermission(Principal principal, String aclPath, String permissionFlag) throws SignOnException {
     AccessControlListIF acl = getAcl(aclPath);
     if (principal != null) {
     return acl.checkPermission(principal.getName(), permissionFlag);
     } else {
     return acl.checkPermission(null, permissionFlag);
     }
     }
     */
    /**
     * Returns permissions of the user in all ACls. Format:
     * ACLName:p1,ACLName:p2,AclName2:p1,
     *
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
            Vector ePerms = acls.get(aclName).getPermissions(user);
            s.append(parsePerms(aclName, ePerms));
        }

        return s.toString();
    }

    /**
     * Parse permissions in an array and composes CSV format.
     *
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
     *
     * @param groups hash of the groups
     * @throws SignOnException if file writing fails
     */
    static void setGroups(Hashtable<String, Group> groups) throws SignOnException {
        permStorage.writeGroups(groups);
    }

    /**
     * HARD-CODED permissions for ACL "localgroups".
     *
     * @return permissions in a hash in required format
     */
    static HashMap groupPermissions() {
        HashMap<String, Permission> gPerms = new HashMap<String, Permission>();
        gPerms.put("v", new PermissionImpl("v"));
        gPerms.put("c", new PermissionImpl("c"));
        gPerms.put("u", new PermissionImpl("u"));

        return gPerms;

    }

    /**
     * Get File module singleton.
     *
     * @return file module
     */
    static Persistence getPersistence() {
        if (permStorage == null) {
            try {
                Class fsClass = Class.forName(persistenceDriver);
                Constructor constructor = fsClass.getConstructor();
                permStorage = (Persistence) constructor.newInstance();
            } catch (Exception e) {
                e.printStackTrace();
            }
            //permStorage = new PersistenceMix(props);
        }
        return permStorage;
    }

    /**
     * Adds a new ACL for a non-folder object under the specified parent ACL.
     *
     * @param aclPath full acl Path - "/datasets/1234"
     * @param owner - the owner of the object - "jaanus"
     * @param description Description of the ACL object - "Lakes"
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
     * @param isFolder indicates if the created object can have children objects
     * @throws SignOnException if ACL exists or DB operation fails
     */
    public static void addAcl(String aclPath, String owner, String description, boolean isFolder) throws SignOnException {

        if (AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("ACL, named " + aclPath + " already exists.");
        }

        try {
            Persistence dbm = getPersistence();
            // if acls in database are not supported, ignore
            if (dbm != null) {
                dbm.addAcl(aclPath, owner, description, isFolder);
            }
        } catch (Exception e) {
            throw new SignOnException("Operation failed : " + e.toString());
        }

        // reset the ACL container
        reset();
    }

    /**
     * Remove an ACL from the application. If the ACL is not held in DB table
     * this API function cannot be used.
     *
     * @param aclPath full ACL path
     * @throws SignOnException if no ACL or no DB support
     */
    public static void removeAcl(String aclPath) throws SignOnException {

        if (!AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("No such ACL: " + aclPath);
        }

        try {
            Persistence dbm = getPersistence();
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
     * Rename ACL. If the ACL is not held in DB table this API function cannot
     * be used.
     *
     * @param aclPath - existing ACL full path
     * @param newAclPath - new ACL full path
     * @throws SignOnException if renaming fails: no ACL or ACL with the new
     * name exists
     */
    public static void renameAcl(String aclPath, String newAclPath) throws SignOnException {

        if (!AccessController.getAcls().containsKey(aclPath)) {
            throw new SignOnException("No such ACL to be renamed: " + aclPath);
        }

        if (AccessController.getAcls().containsKey(newAclPath)) {
            throw new SignOnException("ACL with new name already exists: " + newAclPath);
        }

        try {
            Persistence dbm = getPersistence();
            // if acls in database are not supported, ignore
            if (dbm != null) {
                dbm.renameAcl(aclPath, newAclPath);
            }
        } catch (Exception e) {
            throw new SignOnException("DB operation failed : " + e.toString());
        }
        reset();
    }

    public static AclProperties getAclProperties() {
        return aclProperties;
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
