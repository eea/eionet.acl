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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.acl.Group;
import java.security.acl.Permission;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import eionet.acl.impl.GroupImpl;
import eionet.acl.impl.PermissionImpl;
import eionet.acl.impl.PrincipalImpl;


/**
 * Read and write plain text ACL files.
 */
class AclFileReader {

    /**
     * Read groups and group memberships from a text file. The information is added into two
     * hashmaps as a side-effect.
     *
     * The format is:
     * <pre>
     * group_name:username1,username2,...,username4
     * </pre>
     *
     * @param fileName The name of the file to read from.
     * @param groups
     * @param users
     * @throws SignOnException
     */
    void readGroups(String fileName, HashMap<String, Group> groups, HashMap<String, Principal> users) throws SignOnException  {

        ArrayList<String> uRows = readFileRows(fileName);

        //process the file Rows
        for (Iterator i = uRows.iterator(); i.hasNext();) {
            String ugRow = (String) i.next();
            processLocalGroup(ugRow, groups, users);

        }
    }

    /**
     * Load the lines from a file into a list. The lines are trimmed for spaces.
     * Empty lines are ignored.
     *
     * @param fileName
     * @return a list containing the lines of the file.
     * @throws SignOnException
     */
    ArrayList<String> readFileRows(String fileName) throws SignOnException {

        ArrayList<String> rows = new ArrayList<String>();
        try {
            FileReader fr = new FileReader(fileName);
            BufferedReader  reader  = new BufferedReader(fr);
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                String trimmedLine = line.trim();
                if (trimmedLine.length() > 0)
                    rows.add(trimmedLine);
            }
        } catch (FileNotFoundException noe) {
            throw new SignOnException(noe, "No such file: " + fileName);
        } catch (IOException ioe) {
            throw new SignOnException(ioe, "I/O error reading file: " + fileName);
        }

        return rows;
    }

    /**
     * Split a string containing a group name and members separated by colon.
     *
     * @param ugRow - string containing a group name and members separated by colon.
     * @param groups - hashmap of groups to add discovered groups into.
     * @param users - hashmaps of users and their memberships.
     * @throws SignOnException
     */
    private void processLocalGroup(String ugRow, HashMap<String, Group> groups, HashMap<String, Principal> users) throws SignOnException {
        String grpName = ugRow.substring(0, ugRow.indexOf(":"));
        Group grp = new GroupImpl(grpName);
        groups.put(grpName, grp);

        processUsers(ugRow.substring(ugRow.indexOf(":") + 1), grp, users);

    }

    /**
     *
     * @param usrs
     * @param grp
     * @param users
     * @throws SignOnException
     */
    private void processUsers(String usrs, Group grp, HashMap<String, Principal> users) throws SignOnException {
        StringTokenizer tokenizer = new StringTokenizer(usrs, ",");

        while (tokenizer.hasMoreElements()) {
            String userName = tokenizer.nextToken();
            //l("user=" + userName);
            Principal p = new PrincipalImpl(userName);

            // AclEntry usrEntry = new AclEntryImpl(p);

            if (!users.containsKey(userName))
                users.put(userName, p);

            grp.addMember(p);

        }
    }

    /**
     * Read the permissions from the plain text permissions file.
     *
     * @param fileFullPath
     * @param permissions
     * @param prmDescrs
     * @throws SignOnException
     */
    void readPermissions(String fileFullPath, Map<String, Permission> permissions, Map<String, String> prmDescrs) throws SignOnException {
        ArrayList<String> pRows = readFileRows(fileFullPath);
        for (Iterator i = pRows.iterator(); i.hasNext();) {
            String pRow = (String) i.next();
            processPermissions(pRow, permissions, prmDescrs);
        }
    }

    /**
     * Process a permission description.
     *
     * @param pRow
     * @param permissions
     * @param prmDescrs
     * @throws SignOnException
     */
    private void processPermissions(String pRow, Map<String, Permission> permissions, Map<String, String> prmDescrs) throws SignOnException {
        //StringTokenizer t = new     StringTokenizer(pRow, ":");
        //permissions = new HashMap();
        //char permission = pRow.charAt(0);

        int i = pRow.indexOf(":");
        String permId = pRow.substring(0, i);


        String description = pRow.substring(i + 1);
        Permission perm = new PermissionImpl(permId);

        //l("putting permission to Hash '" + permId + "'");
        permissions.put(permId, perm);

        //description
        prmDescrs.put(permId, description);
    }

    /**
     * Scan the ACL directory for files that can be loaded.
     *
     * @param folderName - name of ACL folder.
     * @return list of File objects.
     * @throws SignOnException
     */
    File[] getAclFiles(String folderName) throws SignOnException {

        File aclDir = new File(folderName);
        if (aclDir.isDirectory())
            return aclDir.listFiles(new ACLFilter());
        else
            throw new SignOnException("Not a directory: " + aclDir);
    }

    /**
     * Filtering of ACL files.
     *
     */
    class ACLFilter implements java.io.FilenameFilter {
        @Override
        public boolean accept(File path, String name) {
            String nameLowerCase = name.toLowerCase();
            return nameLowerCase.endsWith(".acl") || nameLowerCase.endsWith(".acl.xml");
        }
    }

    /**
     * Get the name of the ACL from the file name it is stored in.
     *
     * @param aclFile
     * @return the name of the ACL
     */
    @Deprecated
    String getAclName(File aclFile) {
        String fileName = aclFile.getName();
        int pos = fileName.indexOf(".acl");

        return fileName.substring(0, pos);
    }

    public void writeAcl(String fileFullPath, Map aclAttrs, List<Map> aclEntries) throws SignOnException {
        ArrayList l = setAclEntries(aclEntries);
        writeFileRows(fileFullPath, l);
    }

    public ArrayList<String> setAclEntries(List<Map> aclEntries) throws SignOnException {
        ArrayList<String> l = new ArrayList<String>();

        for (Map e : aclEntries) {
            String eType = (String) e.get("type");
            String eName = (String) e.get("id");
            String ePerms = (String) e.get("perms");

            String aclType = (String) e.get("acltype");

            String eRow = eType + ":" + eName + ":" + ePerms;

            if (aclType != null && !aclType.equals("object"))
                eRow += ":" + aclType;
            l.add(eRow);
        }
        return l;
    }

    /**
     * Write ACL to plain text file format.
     *
     * @param fileName
     * @param fRows
     * @throws SignOnException
     */
    void writeFileRows(String fileName, ArrayList fRows) throws SignOnException {
        try {
            File file = new File(fileName);

            if (!file.canWrite())
                throw new IOException("The system isn't allowed to write to file: " + fileName);

            FileWriter fw = new FileWriter(file);

            BufferedWriter writer = new BufferedWriter(fw);

            for (Iterator i = fRows.iterator(); i.hasNext();) {
                String line = (String) i.next();
                writer.write(line);
                writer.newLine();
            }

            writer.flush();
            writer.close();

        } catch (FileNotFoundException noe) {
            throw new SignOnException("No such file " + fileName);
        } catch (IOException ioe) {
            throw new SignOnException("Error reading acls " + ioe.toString());
        }

    }

}
