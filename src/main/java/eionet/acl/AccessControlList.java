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
 * Copyright (C) 2000-2014 by European Environment Agency.  All
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
 * Since it references members of AccessController in the constructor, it
 * requires that AccessController has been initialised.
 */
class AccessControlList implements AccessControlListIF {

    //where the ACL entries are held: text file, DB, ...
    /**
     * ACL mechanism type.
     * file and DB are supported
     */
    private int mechanismType;

    private String ownerPrm;

    private String anonymousUserName;
    private String authUserName;

    /** Name of ACL object. */
    String name;
    /** Description of ACL object. */
    String description;

    /** Groups are retrieved from the AccessController. */
    private HashMap groups;
    private HashMap users;
    private HashMap permissions;

    private static final Logger LOGGER = Logger.getLogger(AccessControlList.class);

    /**
     * Local container for DOC and DDC entries.
     */
    private List<HashMap<String, String>> docAndDdcEntries;

    Acl acl;
    Principal owner;
    private AclFileReader fReader;

    private Persistence storageManager;

    /**
     * Enum for ACL entry type.
     *
     * @author Kaido Laine
     */
    public enum AclEntryType {
        /** Standard ACL. */
        OBJECT,
        /** Initial Object Creation. When you create a child object that is <em>not</em>
         * folder like then it inherits from the parent's DOC. */
        DOC,
        /** Initial Container Creation. When you create a child object that is
         * folder like then it inherits from the parent's DCC. */
        DCC;
    }

    private static final String[] LEGAL_PRINCIPAL_TYPES =
    {"owner", "user", "localgroup", "other", "foreign", "unauthenticated", "authenticated", "mask", "anonymous", "circarole"};

    /**
     * Initialise variables for ACL not depending on the mechanism.
     */
    AccessControlList(Persistence storage) {
        storageManager = storage;
        groups = AccessController.groups;
        users = AccessController.users;

        permissions = AccessController.permissions;

        //the same for all ACLs
        ownerPrm = AccessController.ownerPrm;

        authUserName = AccessController.authEntry;
        anonymousUserName = AccessController.anonymousEntry;

        //docEntries = new Vector();

        docAndDdcEntries = new ArrayList<HashMap<String, String>>();

    }

    /**
     * Returns ACL entry rows.
     *
     * @return list in format [group|role|user:name:p1,p2,pN]
     */
    @Override
    public Vector<Hashtable<String, String>> getEntryRows() throws SignOnException {

        Vector<Hashtable<String, String>> v = new Vector<Hashtable<String, String>>();

        Enumeration<AclEntry> entries = acl.entries();
        while (entries.hasMoreElements()) {

            AclEntry entry = entries.nextElement();

            //show only positive entries in the ACL Admin Tool
            if (!entry.isNegative()) {

                Principal p = entry.getPrincipal();

                String entryPrms = getEntryPrms(entry);
                String entryName = p.getName();
                String entryType = getPrincipalType(p);

                String eType = getAclTypeText(entryType);

                Hashtable<String, String> e = new Hashtable<String, String>();
                e.put("acltype", "object"); //hard-coded
                e.put("type", eType);
                e.put("perms", entryPrms);
                e.put("id", entryName);

                v.add(e);
            } //positive entries
        }

        //DOC and DDC DDC entries
        for (HashMap<String, String> ddcEntry : docAndDdcEntries) {
            String type = ddcEntry.get("TYPE");
            String principal = ddcEntry.get("PRINCIPAL");
            String perms = ddcEntry.get("PERMISSIONS");
            String aclType = ddcEntry.get("ENTRY_TYPE");

            type = getAclTypeText(type);

            Hashtable<String, String> e = new Hashtable<String, String>();
            e.put("acltype", aclType); //hard-coded
            e.put("type", type);
            e.put("perms", perms);
            e.put("id", principal);

            v.add(e);
        }
        return v;
    }

    /**
     * Returns long representation of ACL type.
     *
     * @param type one letter type
     * @return full text
     */
    private String getAclTypeText(String type) {
        String text = "";
        if (type.equals("G")) {
            text = "localgroup";
        } else if (type.equals("R")) {
            text = "circarole";
        } else if (type.equals("U")) {
            text = "user";
        } else {
            text = "unknown";
        }

        return text;
    }

    /**
     * Permissions of the user.
     * @param user userName
     */
    @Override
    public Vector getPermissions(String user) throws SignOnException {
        Collection prms = new HashSet();
        Principal p;
        Enumeration ePerms;

        if (user.trim().equals(""))
            user = null;

        if (user != null) {
            p = (Principal) users.get(user);

            //user exists in the ACL entry rows, get her permissions
            if (p != null) {
                ePerms = acl.getPermissions(p);

                while (ePerms.hasMoreElements()) {
                    Permission prm = (Permission) ePerms.nextElement();
                    prms.add(prm.toString());

                }
                //return prms;
                Vector v = new Vector(prms);
                return v;
            }

            //user is not described but is authenticated, use "authenticated" entry rows
            p = (Principal) users.get(authUserName);
            if (p != null) {
                ePerms = acl.getPermissions(p);

                while (ePerms.hasMoreElements()) {
                    Permission prm = (Permission) ePerms.nextElement();
                    prms.add(prm.toString());

                }
            }
            Vector v = new Vector(prms);
            return v;
            //return prms;
        }

        //user is not authenticated, check if the "anonymous" entry has permissions
        p = (Principal) users.get(anonymousUserName);
        if (p != null) {
            ePerms = acl.getPermissions(p);

            while (ePerms.hasMoreElements()) {
                Permission prm = (Permission) ePerms.nextElement();
                prms.add(prm.toString());

            }
        }

        Vector v = new Vector(prms);
        return v;

    }

    /**
     * Check if the user has this permission in this ACL.
     * If the user name is null or empty then the user is not authenticated.
     * @param userName username
     * @param permission permission to check
     * @return true if user has permission
     */
    @Override
    public boolean checkPermission(String userName, String permission) throws SignOnException {

        Permission permissionObject = (Permission) permissions.get(permission);
        if (permissionObject == null) {
            throw new SignOnException("Unknown permission: " + permission);
        }

        // anonymous user
        if (userName == null || userName.trim().length() == 0) {
            Principal anonymousPrincipal = (Principal) users.get(anonymousUserName);
            return anonymousPrincipal != null && acl.checkPermission(anonymousPrincipal, permissionObject);
        } else {
            // authenticated user, first try its own name
            Principal principal = (Principal) users.get(userName);
            if (principal != null) {
                if (acl.checkPermission(principal, permissionObject)) {
                    return true;
                }
            }

            // no permission by this user's own name, but since it is still an authenticated user,
            // see if authenticated user has this permission
            Principal authenticatedPrincipal = (Principal) users.get(authUserName);
            return authenticatedPrincipal != null && acl.checkPermission(authenticatedPrincipal, permissionObject);
        }
    }

    /**
     *
     * @param aRows
     * @throws SignOnException
     */
    public void processAclRows(ArrayList aRows) throws SignOnException {

        // Process rows twice.
        // First process group rows because we have to know the group membership already when processing users.

        // 1st processing
        for (Iterator i = aRows.iterator(); i.hasNext();) {
            String aRow = (String) i.next();
            processRights(aRow, false); // false here means we process groups+roles
        }

        // 2nd processing
        for (Iterator i = aRows.iterator(); i.hasNext();) {
            String aRow = (String) i.next();
            processRights(aRow, true); // true here means we process groups+roles
        }

    }

    /**
     * Processes the given ACL row, but skips it if the principal type (e.g. user, localgroup, etc) is not the same
     * as indicated by the given boolean. If the boolean equals true, then the row is skipped
     * if its principal type <em>equals</em> "user".
     * If the boolean equals false, then the row is skipped if its principal type <em>does not equal</em> "user".
     *
     * @param aRow  the given ACL row
     * @param users the boolean as described above
     *
     * @throws SignOnException
     */
    private void processRights(String aRow, boolean users) throws SignOnException {

        int a = aRow.indexOf(":");
        int b = aRow.indexOf(":", a + 1);
        int c = aRow.indexOf(":", b + 1);

        AclEntryType aclType = AclEntryType.OBJECT;

        if (c != -1) {
            String docOrDdc = aRow.substring(c + 1);

            if (docOrDdc.equals("doc")) {
                aclType = AclEntryType.DOC;
            } else if (docOrDdc.equals("dcc")) {
                aclType = AclEntryType.DCC;
            }
        }

        //it is DOC or DDC entry
        boolean isDocOrDdc = (c != -1);

        String principalType = aRow.substring(0, a);
        String principalId = aRow.substring(a + 1, b);
        String principalPermissions = (isDocOrDdc ? aRow.substring(b + 1, c) : aRow.substring(b + 1));

        if (principalType.equals("localgroup") && !users)
            addGroupRights(principalId, principalPermissions, aclType);
        else if (principalType.equals("user") && users)
            addUserRights(principalId, principalPermissions, aclType);
        else if (principalType.equals("circarole") && !users)
            addRoleRights(principalId, principalPermissions, aclType);
        else if (principalType.equals("description") && !users)
            description = principalId;
    }

    /**
     *
     * @param roleName
     * @param permissionsArray
     * @param aclType whether the acl is object, doc or dcc.
     * @throws SignOnException
     */
    public void addRoleRights(String roleName, String permissionsArray, AclEntryType aclType)  throws SignOnException  {

        Group circaRole = new RoleImpl(roleName);

        AclEntry aclGrp = new AclEntryImpl(circaRole);

        /* DBG ->  */
        //      put role occupants to users' container as well (do not know, if necessary)
        Enumeration m = circaRole.members();

        while (m.hasMoreElements()) {
            Principal user = (Principal) m.nextElement();
            users.put(user.getName(), user);
        }
        //      <-

        addPrmsToEntry(aclGrp, permissionsArray);

        if (!aclType.equals(AclEntryType.OBJECT)) {
            docAndDdcEntries.add(aclEntryToHash(aclGrp, permissionsArray, aclType));
        } else {
            try {
                //l("Add AclEntry " + aclGrp.getPrincipal().getName());
                acl.addEntry(owner, aclGrp);
            } catch (NotOwnerException noe) {
                throw new SignOnException("Not owner "  + noe.toString());
            }
        }
    }

    /**
     * Add group rights.
     */
    public void addGroupRights(String groupName, String permissionsArray, AclEntryType aclType)  throws SignOnException  {

        Group grp;
        // !!quick fix group has been deleted but still exists in ACL
        if (!groups.containsKey(groupName)) {
            return;
        }

        grp = (Group) groups.get(groupName);

        AclEntry aclGrp = new AclEntryImpl(grp);

        addPrmsToEntry(aclGrp, permissionsArray);

        if (!aclType.equals(AclEntryType.OBJECT)) {
            docAndDdcEntries.add(aclEntryToHash(aclGrp, permissionsArray, aclType));
        } else {
            try {
                acl.addEntry(owner, aclGrp);
            } catch (NotOwnerException noe) {
                throw new SignOnException("Not owner " + noe.toString());
            }
        }

    }

    private void addPrmsToEntry(AclEntry aclE, String prmA) throws SignOnException {
        String s;
        Permission p;

        int i = 0;
        StringTokenizer prmT = new StringTokenizer(prmA, ",");

        while (prmT.hasMoreTokens()) {
            s = prmT.nextToken();

            p = (Permission) permissions.get(s);

            if (p == null) {
                throw new SignOnException("Unknown permission: " + s);
            }

            //Pricncipal is an owner
            if (s.equals(ownerPrm)) {
                try {
                    acl.addOwner(owner, aclE.getPrincipal());
                } catch (NotOwnerException noe) {
                    throw new SignOnException("CAnnot be owner: " + noe.toString());
                }
            }
            aclE.addPermission(p);
        }

    }

    /**
     * Add user rights.
     */
    public void addUserRights(String userName, String permissionsArray, AclEntryType aclType) throws SignOnException  {
        Principal user = (Principal) users.get(userName);
        Permission oPrm = (Permission) permissions.get(ownerPrm);

        //create a new one?
        if (user == null) {
            user = new PrincipalImpl(userName);
            users.put(userName, user);

        }

        HashMap uGroups = isMemberOf(user);
        AclEntry uNegativeEntry = null;
        //set Negative permissions
        //check if any of groups, user belongs to is set as this ACL entry
        Enumeration aclEntries = acl.entries();
        while (aclEntries.hasMoreElements()) {
            AclEntry aclE  = (AclEntry) aclEntries.nextElement();

            //group where user belongs to is listed in ACL as separate entry
            if (uGroups.containsKey(aclE.getPrincipal())) {
                //find out group entries and set as negative for users first
                Enumeration gPerms = aclE.permissions();
                uNegativeEntry = new AclEntryImpl(user);
                while (gPerms.hasMoreElements()) {
                    uNegativeEntry.addPermission((Permission) gPerms.nextElement());
                }
                uNegativeEntry.setNegativePermissions();
                //acl.addEntry(owner,uNegativeEntry);
            }

        }

        AclEntry aclUsr = new AclEntryImpl(user);
        addPrmsToEntry(aclUsr, permissionsArray);


        if (!aclType.equals(AclEntryType.OBJECT)) {
            docAndDdcEntries.add(aclEntryToHash(aclUsr, permissionsArray, aclType));
        } else {
            try {
                if (uNegativeEntry != null)
                    acl.addEntry(owner, uNegativeEntry);


                //if the user is an owner she has to have the owner permission
                if (user.equals(owner) && !aclUsr.checkPermission(oPrm))
                    aclUsr.addPermission(oPrm);

                acl.addEntry(owner, aclUsr);


            } catch (NotOwnerException noe) {
                throw new SignOnException("Not owner + " + noe.toString());
            }
        }
    }


    private String  getEntryPrms(AclEntry entry) {
        String entryPrms = "";

        //type = getPrincipalType(p);
        Enumeration perms = entry.permissions();

        while (perms.hasMoreElements()) {
            entryPrms = entryPrms + ((Permission) perms.nextElement()).toString() + ",";
        }

        if (!entryPrms.equals("")) {
            entryPrms = entryPrms.substring(0, entryPrms.length() - 1);
        }
        return entryPrms;
    }

    private String getPrincipalType(Principal p) {
        String type = "";
        if (p instanceof RoleImpl)
            type = "R";
        else  if (p instanceof GroupImpl)
            type = "G";
        else
            type = "U";
        return type;
    }


    @Override
    public void setAcl(Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
        LOGGER.debug("setAcl()");
        storageManager.writeAcl(name, aclAttrs, aclEntries);
    }

    @Override
    public void setAclEntries(Vector aclEntries) throws SignOnException {
        setAcl(null, aclEntries);
    }

    @Override
    public boolean isOwner(String userName) {

        if (userName == null)
            userName = anonymousUserName;
        else if (userName.equals(this.name))
            return acl.isOwner(new PrincipalImpl(userName));
        else {
            if (!users.containsKey(userName)) {
                userName = authUserName; //if not listed in ACL check auth user
                if (!users.containsKey(userName))
                    userName = anonymousUserName; //if not listed in ACL check unauth user
            }
        }

        if (!users.containsKey(userName))
            return false;

        return acl.isOwner((Principal) users.get(userName));
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDescription() {
        return description;
    }

    public void setDescription(String sDescription) {
        this.description = sDescription;
    }

    //  check if user entries exist in ACL and set negative groupPerms

    /**
     * Hashmap of groups where the user is member of.
     * @param user User
     */
    private HashMap isMemberOf(Principal user) {
        HashMap grpNames = new HashMap();
        for (Iterator i = groups.keySet().iterator(); i.hasNext();) {
            Group g = (Group) groups.get(i.next());
            if (g.isMember(user))
                grpNames.put(g, g.getName());
        }


        return grpNames;
    }

    //translate AclE to understandable format for DB module: aclE
    private HashMap aclEntryToHash(AclEntry aclE, String permissionsArray, AclEntryType entryType) {

        HashMap h = new HashMap();
        String eName = aclE.getPrincipal().getName();
        String type = getPrincipalType(aclE.getPrincipal());

        h.put("TYPE", type);

        h.put("PRINCIPAL", eName);
        h.put("PERMISSIONS", permissionsArray);

        //!!! at the moment hard-coded, used only if DOC ACL's may need changing in the future
        String entryTypeText = "object";

        if (entryType.equals(AclEntryType.DOC)) {
            entryTypeText = "doc";
        } else if (entryType.equals(AclEntryType.DCC)) {
            entryTypeText = "dcc";
        }

            //h.put("ENTRY_TYPE", "doc");

        h.put("ENTRY_TYPE", entryTypeText);

        return h;
    }

    @Override
    public List<HashMap<String, String>> getDOCAndDCCEntries() throws SignOnException {
        return docAndDdcEntries;
    }

    /**
     * The mechanism() is legacy from when file and DB  based ACLs were implemented
     * as the same class.
     */
    @Override
    public int mechanism() {
        return mechanismType;
    }

    protected void setMechanism(int mechanism) {
        mechanismType = mechanism;
    }

    /**
     * Check if the Principal type is on the list of LEGAL_PRINCIPAL_TYPES.
     *
     * @param principalType
     * @return true if it is.
     */
    public static boolean isLegalPrincipalType(String principalType) {
        if (principalType == null || principalType.length() == 0)
            return false;
        for (int i = 0; i < LEGAL_PRINCIPAL_TYPES.length; i++) {
            if (LEGAL_PRINCIPAL_TYPES[i].equals(principalType))
                return true;
        }

        return false;
    }

    public String toString() {
        return "Name: " + name + "\n" + acl.toString();
    }
}
