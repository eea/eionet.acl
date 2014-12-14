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
 * @ver 3.0 doc ACLs
 * @ver 3.1 Children ACLs sorted alphabetically
 */

package eionet.acl;

import java.text.Collator;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

import org.apache.log4j.Logger;

/**
 * Adapter class for RPC method calls.
 */
public class RemoteService {
    AppUser _user;

    private static Logger LOGGER = Logger.getLogger(RemoteService.class);

    public RemoteService()  {}

    public RemoteService(AppUser user)  {
        _user = user;
    }

    /**
     * Returns entries of the ACL.
     * Array of Strings as described in *.acl files:
     * <pre>
     * localgroup:x_admin:s,f,r
     * user:john:s,y0,c
     * </pre>
     */
    public Hashtable getAclInfo(String aclName) throws SignOnException  {

        if (_user == null)
            throw new SignOnException("Not authenticated");

        AccessControlListIF acl = AccessController.getAcl(aclName);
        /*
         if (! acl.isOwner(_user.getUserName()))
         throw new SignOnException("Not owner");
         */
        Hashtable aclInfo = new Hashtable();
        String descr = acl.getDescription();

        aclInfo.put("name", aclName);
        aclInfo.put("description" , descr);

        //hard coded !!!
        if (aclName.equals("/localgroups"))
            aclInfo.put("flags", "groupperms");
        else
            aclInfo.put("flags", "tableperms");

        Vector entries=  acl.getEntryRows();
        aclInfo.put("entries", entries);

//      System.out.println("======== entries: " + entries.size());

        aclInfo.put("owner", new Boolean(acl.isOwner(_user.getUserName())).toString());

        //where the ACL data is stored
        //aclInfo.put("mechanism", new Integer(acl.mechanism()));

        return aclInfo;
    }

    /**
     * RPC method for returning ACL names of the parent ACL
     * Example: getChildrenAcls("/") = ["/RO", "/RA", "/LI"]
     */

    public Vector getChildrenAcls(String parentAclName) throws SignOnException {
        if (_user == null)
            throw new SignOnException("Not authenticated");

        AccessControlListIF parentAcl = AccessController.getAcl(parentAclName);

        // We cannot authorise here with c-permission because the user who is not admin of
        // the parent ACL may be the admin of the child ACL

        Vector v = new Vector();
        HashMap acls = AccessController.getAcls();
        for (Iterator i = acls.keySet().iterator(); i.hasNext();) {
            String aclName=(String) i.next();
            AccessControlListIF acl = (AccessControlListIF) acls.get(aclName) ;

            if (! aclName.equals(parentAclName) &&
                    aclName.length() >= parentAclName.length() &&
                    aclName.substring(0, parentAclName.length()).equals(parentAclName) &&
                    aclName.indexOf("/", parentAclName.length()+1) == -1)

                v. add(aclName);
        }

        //acl.isOwner(_user.getUser()

        //sort alphabetically
        Collator collator = Collator.getInstance();
        Collections.sort(v,collator);

        return v;
    }

    /**
     * RPC method for returning all ACL names of the application
     * Example: getAcls() = ["/RO", "/RA", "/LI"]
     */

    public Vector getAcls() throws SignOnException {

        if (_user == null)
            throw new SignOnException("Not authenticated");

        Vector v = new Vector();
        HashMap acls = AccessController.getAcls();
        for (Iterator i = acls.keySet().iterator(); i != null && i.hasNext();)
            v.add(i.next());

        //sort alphabetically
        Collator collator = Collator.getInstance();
        Collections.sort(v,collator);

        return v;
    }

    /**
     * RPC method for returning infos of all ACLs in the application.
     * Returns a Hashtable where every key marks an ACL name and the
     * matching value is a Hashtable representation of the ACL info.
     * The latter contains also the ACL's entries (get the "entries" key).
     * Each entry is an array of Strings as described in *.acl files:
     *  localgroup:x_admin:s,f,r
     *  user:john:s,y0,c
     */
    public Hashtable getAclInfos() throws SignOnException {

        if (_user == null)
            throw new SignOnException("Not authenticated");

        Hashtable result = new Hashtable();
        HashMap acls = AccessController.getAcls();
        for (Iterator i = acls.keySet().iterator(); i != null && i.hasNext();) {
            String aclName = (String) i.next();
            Hashtable aclInfo = getAclInfo(aclName);
            result.put(aclName, aclInfo);
        }

        return result;
    }

    /**
     * AclManagerInfo:
     * hard-codeed as a quick-fix
     */
    public Hashtable getAclManagerInfo() throws SignOnException {

        if (_user == null)
            throw new SignOnException("Not authenticated");

        Hashtable h = new Hashtable();
        h.put("minor_ver", "1.0");
        h.put("major_ver", "4.0");

        Hashtable flags = new Hashtable();

        //name hard-coded !!!
        flags.put("tableperms", AccessController.prmDescrs);

        //localgroup permissions hard-coded now:
        Hashtable gPerms = new Hashtable();
        gPerms.put("v", "View");
        gPerms.put("u", "Update");
        gPerms.put("c", "Control");
        flags.put("groupperms", gPerms);


        h.put("flags", flags);

        Vector eTypes = new Vector();
        Hashtable eType = new Hashtable();

        eType.put("type", "user");
        eType.put("arg", "y");

        eTypes.add(eType);

        eType = new Hashtable();
        eType.put("type", "circarole");
        eType.put("arg", "y");

        eTypes.add(eType);

        eType = new Hashtable();
        eType.put("type", "localgroup");
        eType.put("arg", "y");

        eTypes.add(eType);

        h.put("entrytypes", eTypes);

        h.put("control_flag", "c");
        h.put("ownership", "true");


        return h;
    }
    /**
     * RPC method, return localgroups
     * Struct: key: group name, value: Array of Strings[user names]
     */
    public Hashtable getLocalGroups() throws SignOnException {
        if (_user == null)
            throw new SignOnException("Not authenticated");


        String aclName, permFlag;

        if (AccessController.getAcls().containsKey("/localgroups")) {
            aclName="/localgroups";
            permFlag="v"; //hard coded!
        }
        else {
            aclName = "/"; //use ROOt instead if not localgroups ACL
            permFlag= AccessController.ownerPrm;  //require control permission of ROOT
        }


        AccessControlListIF grpAcl = AccessController.getAcl(aclName);
        //must have control permission over root ACL

        boolean isAllowed = grpAcl.checkPermission(_user.getUserName(), permFlag);
        if (!isAllowed)
            return new Hashtable();
        else
            return AccessController.getGroups();

    }

    /**
     * RPC method, returns human readable permission descriptions
     * Returns: Struct: key=permission id, value: permission description
     * Example: { r:Read, w:Write, c:Control  }
     */
    /*public Hashtable getPermissionDescrs() throws SignOnException {

     //allow all authenticated users
      if (_user == null)
      throw new SignOnException("Not authenticated");


      return AccessController.prmDescrs;
      } */


    /**
     * RPC method: permissions for the user in the ACL.
     *
     * @param userName - user name
     * @param aclName - path name of ACL
     * @return java.util.Vector = XML/RPC ARRAY
     */
    public Vector getUserPermissions(String userName, String aclName) throws SignOnException {

        if (_user == null)
            throw new SignOnException("Not authenticated");

        AccessControlListIF acl = AccessController.getAcl(aclName);

        //user must have the control access over the ACL
        if (! acl.isOwner(_user.getUserName()))
            throw new SignOnException("Not owner of " + aclName);

        Vector prms = acl.getPermissions(userName);

        return prms;

    }
    /**
     * Saves entries of the ACL.
     *
     * @param aclInfo - the same structure as returned by getAclEntries method
     * @return String because XML/RPC does not support null
     */
    public String setAclInfo(Hashtable aclInfo) throws SignOnException {
        String aclName = (String) aclInfo.get("name");
        LOGGER.debug("setAclInfo() " + aclName);
        AccessControlListIF acl = AccessController.getAcl(aclName);
        String userName = (_user == null ? null : _user.getUserName());

        // control permission for the ACL is needed
        if (!acl.isOwner(userName))
            throw new SignOnException("Not owner of ACL");

        Vector aclEntries = (Vector) aclInfo.get("entries");
        LOGGER.debug("ACL " + aclName + " entries size=" + aclEntries.size());
        Map aclAttrs = new HashMap();
        String aclDescription = (String) aclInfo.get("description");
        if (aclDescription != null)
            aclAttrs.put("description", aclDescription);

        acl.setAcl(aclAttrs.size() == 0 ? null : aclAttrs, aclEntries);
        LOGGER.debug("ACL " + aclName + " entries set successfully.");

        AccessController.reset();

        return "OK";
    }

    /**
     * w permission of /localgroups ACL needed
     * if not such ACL, '/' is used
     */

    public String setLocalGroups (Hashtable groups) throws SignOnException {
        if (_user == null)
            throw new SignOnException("Not authenticated");

        String aclName, permFlag;

        if (AccessController.getAcls().containsKey("/localgroups")) {
            aclName="/localgroups";
            permFlag="u"; //hard coded!
        }
        else {
            aclName = "/"; //use ROOt instead if not localgroups ACL
            permFlag= AccessController.ownerPrm;  //require control permission of ROOT
        }

        AccessControlListIF acl = AccessController.getAcl(aclName);

        String userName=  (_user == null ? null : _user.getUserName());

        if (! acl.checkPermission(userName, permFlag))
            throw new SignOnException("Not allowed to change localgroups");

        AccessController.setGroups(groups);

        AccessController.reset();
        return "OK";
    }

    public static String[] methodNames() {
        String r[]={"getAclInfo", "getLocalGroups", "getChildrenAcls",
                "getUserPermissions",   "setAclInfo", "setLocalGroups", "getAclManagerInfo", "getAcls", "getAclInfos"};
        return r;
    }

    public static String[] valueTypes() {
        String r[]={"STRUCT", "STRUCT", "ARRAY", "ARRAY", "STRING", "STRING", "STRUCT", "ARRAY", "STRUCT"};
        return r;
    }

}
