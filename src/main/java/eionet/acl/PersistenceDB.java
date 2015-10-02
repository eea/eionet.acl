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

import eionet.acl.impl.AclImpl;
import eionet.acl.impl.PrincipalImpl;
import eionet.propertyplaceholderresolver.ConfigurationPropertyResolver;
import java.security.acl.Group;
import java.security.Principal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;
import javax.sql.DataSource;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * DB operations implementation. Expects two tables in the database: ACLS and
 * ACL_ROWS.
 */
public class PersistenceDB implements Persistence {

    /**
     * logger instance.
     */
    private static final Logger LOGGER = Logger.getLogger(PersistenceDB.class);

    DataSource dataSource = null;
    String dbUrl, dbDriver, dbUser, dbPwd;

    PersistenceDB(ConfigurationPropertyResolver configurationPropertyResolver) throws DbNotSupportedException {
        try {
            dbUrl = configurationPropertyResolver.resolveValue("db.url");
            dbDriver = configurationPropertyResolver.resolveValue("db.driver");
            dbUser = configurationPropertyResolver.resolveValue("db.user");
            dbPwd = configurationPropertyResolver.resolveValue("db.pwd");
            checkAclTables();
        } catch (DbNotSupportedException dbne) {
            LOGGER.info("Database Not supported " + dbne);
            throw dbne;
        } catch (SQLException sqle) {
            LOGGER.error("Error in database checking " + sqle);
            throw new DbNotSupportedException();
        } catch (Exception e) {
            LOGGER.error("Error in database checking " + e);
            throw new DbNotSupportedException();
        }
    }

    /**
     * Checks ACL tables existance.
     *
     * @throws SQLException in case of different database errors: wrong
     * configuration, database is down etc
     * @throws DbNotSupportedException if no ACL tables
     */
    private void checkAclTables() throws SQLException, DbNotSupportedException {

        if (dbDriver == null && dataSource == null) {
            throw new SQLException("No Database Connection");
        }

        //boolean result = false;
        Connection conn = null;
        try {
            conn = getConnection();

            try {
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("select count(*) from ACLS");
                ResultSet rs2 = stmt.executeQuery("select count(*) from ACL_ROWS");
                //no tables assume ACLs in DB is not supported
            } catch (SQLException sqle) {
                throw new DbNotSupportedException("Error checking ACL tables " + sqle);
            }
        } finally {
            try {
                if (conn != null) {
                    conn.close();
                }
            } catch (Exception e) {
                LOGGER.error("Error in closing connection " + e);
            }
        }

        //return result;
    }

    @Override
    public void addAcl(String aclPath, String owner, String description) throws SQLException, SignOnException {
        addAcl(aclPath, owner, description, false);
    }

    @Override
    public void addAcl(String aclPath, String owner, String description, boolean isFolder) throws SQLException, SignOnException {

        if (owner == null) {
            throw new SignOnException("The owner of ACL cannot be null.");
        }

        int lastSlash = aclPath.lastIndexOf("/");

        if (lastSlash == -1) {
            throw new SignOnException("Invalid ACL Path, must contain at least one '/'");
        }

        //get the parent ACl and if it has DOC and DCC entry rows, process them
        String parentName = (lastSlash == 0 ? "/" : aclPath.substring(0, lastSlash));
        String aclName = aclPath.substring(lastSlash + 1);

        AccessControlListIF parentAcl = AccessController.getAcl(parentName);

        description = description == null ? "" : description;

        String sql = "INSERT INTO ACLS (ACL_NAME, PARENT_NAME, OWNER, DESCRIPTION) VALUES('" + aclName + "', '" + parentName
                + "','" + owner + "', '" + description + "')";

        executeUpdate(sql);

        List<HashMap<String, String>> dccEntries = parentAcl.getDOCAndDCCEntries();

        //just added ACL id
        String aclId = getMaxAclId();

        processDocAndDccEntries(aclId, dccEntries, owner, isFolder);

    }

    /**
     * special handling for DOC and DDC entries.
     *
     * @param aclId ACL ID
     * @param docAndDccEntries list of DOC and DCC entries
     * @param owner ACL owner
     * @param isFolder true if can have sub-folders
     * @throws SQLException if inserts fail
     */
    private void processDocAndDccEntries(String aclId, List<HashMap<String, String>> docAndDccEntries, String owner,
            boolean isFolder) throws SQLException {

        String sql;

        // {ENTRY_TYPE=doc, PERMISSIONS=d,u,c, PRINCIPAL=owner, TYPE=U}
        // if a user is a DOC ACL and she is the owner as well only the owner permissions are granted!!
        // add default DCC entry if no DCC entries:
        createDefaultDCCEntries(docAndDccEntries, isFolder);

        // if (docAndDccEntries.size() > 0) {
        HashMap<String, String> ownerE = null;

        for (HashMap<String, String> aclEntry : docAndDccEntries) {

            String eName = aclEntry.get("PRINCIPAL");
            String type = translateEntryType(aclEntry.get("TYPE"));
            String eType = aclEntry.get("ENTRY_TYPE");

            String permissions = aclEntry.get("PERMISSIONS");

            // first copy the DCC or DOC entry to the ACL if folders are supported:
            if (isFolder) {
                sql
                        = "INSERT INTO ACL_ROWS (ACL_ID, ENTRY_TYPE, TYPE, PRINCIPAL, PERMISSIONS, STATUS) "
                        + " VALUES (" + aclId + ", '" + type + "','" + eType + "','" + eName + "','" + permissions + "', 1)";
                executeUpdate(sql);
            }

            // it is DCC ACL but we are adding a regular ACL row so the permissions are for object:
            // TODO is this check needed: it is always doc or dcc
            if (eType.equals("dcc") || eType.equals("doc")) {
                eType = "object";
            }

            // if it is DOC-owner ACL, remember the entry row for further processing, not process now
            if (eName.equals("owner") && type.equals("user")) {
                ownerE = aclEntry;
            } else {
                // check if this already exists:
                String entryPermissions = getEntryPermissions(aclId, eType, type, eName);

                if (entryPermissions == null) {
                    // TODO - change type and entry_type
                    sql
                            = "INSERT INTO ACL_ROWS (ACL_ID, ENTRY_TYPE, TYPE, PRINCIPAL, PERMISSIONS, STATUS) "
                            + " VALUES (" + aclId + ", '" + type + "','" + eType + "','" + eName + "','" + permissions + "', 1)";
                } else {
                    entryPermissions = mergePermissions(entryPermissions, permissions);
                    sql
                            = "UPDATE ACL_ROWS SET PERMISSIONS = '" + entryPermissions + "' WHERE ACL_ID=" + aclId
                            + " AND ENTRY_TYPE='" + type + "' AND TYPE='" + eType + "' AND PRINCIPAL='" + eName + "'";
                }
                executeUpdate(sql);
            }
        }

        // if there is an owner DOC ACL entry, process it:
        if (ownerE != null) {
            // check if the owner user already exists in ACL ROWS:
            // NB If it does we take only OWNER DOC permissions into account and ignore the rest (given by regular ACL entries)
            sql
                    = "SELECT PERMISSIONS FROM ACL_ROWS " + " WHERE ACL_ID = " + aclId + " AND ENTRY_TYPE='user' AND "
                    + " TYPE='object' AND PRINCIPAL ='" + owner + "'";
            String[][] r = executeStringQuery(sql);
            if (r.length == 0) { // not existing
                sql
                        = "INSERT INTO ACL_ROWS (ACL_ID, ENTRY_TYPE, TYPE, PRINCIPAL, PERMISSIONS, STATUS) "
                        + " VALUES (" + aclId + ", 'user','object','" + owner + "','" + ownerE.get("PERMISSIONS") + "', 1)";

            } else { // exists, replace the PERMISSIONS
                sql
                        = "UPDATE ACL_ROWS SET PERMISSIONS='" + ownerE.get("PERMISSIONS") + "'" + " WHERE ACL_ID = " + aclId
                        + " AND ENTRY_TYPE='user' AND " + " TYPE='object' AND PRINCIPAL ='" + owner + "'";
            }

            executeUpdate(sql);
        }
        // }
    }

    /**
     * If no DCC entries add default DCC entry for the owner to prevent creation
     * of ACL with no permissions.
     *
     * @param docAndDccEntries entries list
     * @param folder if a folder is created
     */
    private void createDefaultDCCEntries(List<HashMap<String, String>> docAndDccEntries, boolean folder) {

        boolean hasDocEntries = false;
        boolean hasDccEntries = false;

        for (HashMap<String, String> entry : docAndDccEntries) {
            String eType = entry.get("ENTRY_TYPE");
            if (eType.equalsIgnoreCase("doc")) {
                hasDocEntries = true;
            }
            if (eType.equalsIgnoreCase("dcc")) {
                hasDccEntries = true;
            }
        }

        // {ENTRY_TYPE=doc, PERMISSIONS=d,u,c, PRINCIPAL=owner, TYPE=U}
        if (!hasDocEntries && !folder) {
            HashMap<String, String> defaultDoc = new HashMap<String, String>();
            defaultDoc.put("ENTRY_TYPE", "doc");
            defaultDoc.put("PERMISSIONS", AccessController.defaultDocAndDccPermissions);
            defaultDoc.put("PRINCIPAL", "owner");
            defaultDoc.put("TYPE", "U");

            docAndDccEntries.add(defaultDoc);
        }

        if (!hasDccEntries && folder) {
            HashMap<String, String> defaultDcc = new HashMap<String, String>();
            defaultDcc.put("ENTRY_TYPE", "dcc");
            defaultDcc.put("PERMISSIONS", AccessController.defaultDocAndDccPermissions);
            defaultDcc.put("PRINCIPAL", "owner");
            defaultDcc.put("TYPE", "U");

            docAndDccEntries.add(defaultDcc);
        }
    }

    @Override
    public void removeAcl(String aclPath) throws SQLException, SignOnException {
        int lastSlash = aclPath.lastIndexOf("/");

        if (lastSlash == -1) {
            throw new SignOnException("Invalid ACL Path, must contain at least one '/'");
        }

        //get the aprent ACl and see if it has DOC entry rows
        String parentName = (lastSlash == 0 ? "/" : aclPath.substring(0, lastSlash));
        String aclName = aclPath.substring(lastSlash + 1);

        String sql = "SELECT ACL_ID FROM ACLS WHERE PARENT_NAME='" + parentName + "' AND ACL_NAME='" + aclName + "'";

        String[][] r = executeStringQuery(sql);
        String aclId = null;

        if (r.length == 0) {
            throw new SignOnException("No such ACL " + aclPath);
        } else {
            aclId = r[0][0];
            sql = "DELETE FROM ACL_ROWS WHERE ACL_ID=" + aclId;
            executeUpdate(sql);
            sql = "DELETE FROM ACLS WHERE ACL_ID=" + aclId;
            executeUpdate(sql);
        }
    }

    @Override
    public void renameAcl(String aclPath, String newAclPath) throws SQLException, SignOnException {
        int lastSlash = aclPath.lastIndexOf("/");

        if (lastSlash == -1) {
            throw new SignOnException("Invalid ACL Path, must contain at least one '/'");
        }

        String parentName = (lastSlash == 0 ? "/" : aclPath.substring(0, lastSlash));
        String aclName = aclPath.substring(lastSlash + 1);

        //new Acl name
        lastSlash = newAclPath.lastIndexOf("/");

        if (lastSlash == -1) {
            throw new SignOnException("Invalid ACL Path in New ACL name, must contain at least one '/'");
        }

        String newParentName = (lastSlash == 0 ? "/" : newAclPath.substring(0, lastSlash));
        String newAclName = newAclPath.substring(lastSlash + 1);

        if (!newParentName.equalsIgnoreCase(parentName)) {
            throw new SignOnException("Parent names are not equal");
        }

        String sql = "UPDATE ACLS SET acl_name = '" + newAclName
                + "' WHERE PARENT_NAME='" + parentName + "' AND ACL_NAME='" + aclName + "'";

        executeUpdate(sql);

    }

    private String[][] executeStringQuery(String sql) throws SQLException {
        Vector<String[]> rvec = new Vector<String[]>(); // Return value as Vector
        String[][] rval = {};       // Return value
        Connection con = null;
        Statement stmt = null;
        ResultSet rset = null;

        // Process the result set
        con = getConnection();

        try {
            stmt = con.createStatement();
            rset = stmt.executeQuery(sql);
            ResultSetMetaData md = rset.getMetaData();

            //number of columns in the result set
            int colCnt = md.getColumnCount();

            while (rset.next()) {
                String[] row = new String[colCnt]; // Row of the result set

                // Retrieve the columns of the result set
                for (int i = 0; i < colCnt; ++i) {
                    row[i] = rset.getString(i + 1);
                }
                rvec.addElement(row);
            }
        } catch (SQLException e) {
            e.printStackTrace(System.out);
            throw new SQLException("Error occurred when processing result set: " + sql);
        } finally {

            close(con, stmt, null);
        }

        // Build return value
        if (rvec.size() > 0) {
            rval = new String[rvec.size()][];

            for (int i = 0; i < rvec.size(); ++i) {
                rval[i] = (String[]) rvec.elementAt(i);
            }
        }

        // Success
        return rval;
    }

    private void close(Connection con, Statement stmt, ResultSet rset) throws SQLException {
        try {
            if (rset != null) {
                rset.close();
            }
            if (stmt != null) {
                stmt.close();
                if (!con.getAutoCommit()) {
                    con.commit();
                }
            }
        } catch (Exception e) {
            throw new SQLException("Error" + e.getMessage());
        } finally {
            try {
                con.close();
            } catch (SQLException e) {
                throw new SQLException("Error" + e.getMessage());
            }
        }
    }

    /**
     * Returns new database connection.
     *
     * @throws ServiceException if no connections were available.
     */
    public Connection getConnection() throws SQLException {
        Connection con = null;
        try {
            if (dataSource != null) {
                con = dataSource.getConnection();
            } else {
                Class.forName(dbDriver);
                con = DriverManager.getConnection(dbUrl, dbUser, dbPwd);
            }
        } catch (Throwable t) {
            //set global variable to false to make the AccessController to read ACLS from the database until it is fixed
            AccessController.dbInError = true;
            throw new SQLException("Failed to get database connection " + t);
        }
        AccessController.dbInError = false;
        return con;
    }

    private int executeUpdate(String sql) throws SQLException {
        Connection con = null; // Connection object
        Statement stmt = null; // Statement object
        int rval = 0;          // Return value
        // Get connection object
        con = getConnection();

        // Create statement object
        try {
            stmt = con.createStatement();
        } catch (SQLException e) {
            // Error handling
            //   logger.error( "UpdateStatement failed: " + e.toString());
            // Free resources
            try {
                close(con, stmt, null);
            } catch (Throwable exc) {
                throw new SQLException("_close() failed: " + sql);
            }
            //logger.error("Connection.createStatement() failed: " + sql_stmt,e);
            throw new SQLException("Update failed: " + sql);
        }

        // Execute update
        try {
            LOGGER.debug("SQL " + sql);
            rval = stmt.executeUpdate(sql);
        } catch (Exception e) {
            // Error handling
            throw new SQLException("Statement.executeUpdate(" + sql + ") failed" + e.getMessage());
        } finally {
            // Free resources
            close(con, stmt, null);
        }
        // Success
        return rval;
    }

    private String getMaxAclId() throws SQLException {
        String sql = "SELECT MAX(ACL_ID) FROM ACLS ";
        String[][] ret = executeStringQuery(sql);

        if (ret.length > 0) {
            return ret[0][0];
        }

        return null;
    }

    //TODO this is code duplication also in AccesscontrolList class
    private String translateEntryType(String entryType) {
        if (entryType.equals("G")) {
            return "localgroup";
        } else if (entryType.equals("R")) {
            return "circarole";
        } else if (entryType.equals("U")) {
            return "user";
        } else {
            return "unknown";
        }
    }

    @Override
    public void initAcls(HashMap<String, AccessControlListIF> acls) throws SQLException, SignOnException {

        String sql = "SELECT ACL_ID, ACL_NAME, PARENT_NAME, DESCRIPTION, OWNER FROM ACLS";

        String[][] r = null;
        r = executeStringQuery(sql);
        for (int i = 0; i < r.length; i++) {
            String aclId = r[i][0];
            String aclName = r[i][2] + (r[i][2].equals("/") ? "" : "/") + r[i][1];
            String description = r[i][3];
            String owner = r[i][4];

            sql = "SELECT TYPE, ENTRY_TYPE, PRINCIPAL, PERMISSIONS FROM ACL_ROWS WHERE ACL_ID=" + aclId;
            String[][] aclRows = executeStringQuery(sql);

            AccessControlList acl = readAclDB(aclName, owner, description, aclRows);

            acls.put(aclName, acl);
        }

    }

    /**
     * Construct ACL from the database query.
     */
    private AccessControlList readAclDB(String name, String ownerName, String description, String[][] aclRows)
            throws SignOnException {
        AccessControlList acl = new AccessControlList(this);

        acl.setMechanism(AccessControlListIF.DB);
        //we have to set a fake owner if there is no owner specified in the ACL
        if (ownerName == null || ownerName.equals("")) {
            acl.owner = new PrincipalImpl(name);
        } else {
            acl.owner = new PrincipalImpl(ownerName);
        }

        acl.acl = new AclImpl(acl.owner, name);
        acl.description = description;
        acl.name = name;

        readAclRowsFromDb(aclRows, acl);
        return acl;
    }

    /**
     * Parse ACL rows originating from Database.
     */
    private void readAclRowsFromDb(String[][] aclRows, AccessControlList acl) throws SignOnException {
        ArrayList<String> aRows = new ArrayList<String>();
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
            if (eType.equals("owner")) {
                eType = "user"; //not supported yet
            }
            String aRow = eType + ":" + principal + ":" + perms;

            if (!type.equalsIgnoreCase("object")) {
                aRow = aRow + ":" + type;
            }
            aRows.add(aRow);
        }
        acl.processAclRows(aRows);
    }

    /**
     * Stores ACL in the DB table. The <code>aclAttrs</code> is unused. You
     * can't currently change the description in the database.
     *
     * @param aclName ACL path
     * @param aclAttrs - A map of attributes. The "description" is an attribute.
     * @param aclEntries list of ACL Entries
     * @throws SQLException if DB operation fails
     * @throws SignOnException if no such ACL with given name
     */
    @Override
    public void writeAcl(final String aclName, Map<String, String> aclAttrs, List aclEntries) throws SignOnException {

        ArrayList<String> aclEntriesAsRows = aclEntriesToFileRows(aclEntries);
        // split parent and acl name
        String parentName = null;
        String leafName = null;
        if (!aclName.equals("/")) {
            if (aclName.lastIndexOf("/") == 0) {
                parentName = "/";
                leafName = aclName.substring(1);
            } else {
                parentName = aclName.substring(0, aclName.lastIndexOf("/"));
                leafName = aclName.substring(aclName.lastIndexOf("/") + 1);
            }
        }

        try {
            String sql = "SELECT ACL_ID, ACL_NAME, DESCRIPTION FROM ACLS WHERE ACL_NAME='"
                    + leafName + "' AND " + " PARENT_NAME='" + parentName + "'";

            String aclId;
            String[][] r = executeStringQuery(sql);
            if (r.length == 0) {
                throw new SignOnException("No such ACL=" + aclName);
            } else {
                aclId = r[0][0];
            }

            // update status -> backup rows
            sql = "UPDATE ACL_ROWS SET STATUS='0' WHERE ACL_ID=" + aclId;
            executeUpdate(sql);
            LOGGER.debug("Backup done, entries in the ACL " + r.length);
            // process rows in the list, add into DB
            try {
                LOGGER.debug("Going to save entries, size " + aclEntriesAsRows.size());
                for (int i = 0; i < aclEntriesAsRows.size(); i++) {
                    saveAclEntry(aclId, aclEntriesAsRows.get(i));
                }
            } catch (Exception e) {
                //recover old rows
                sql = "DELETE FROM ACL_ROWS WHERE STATUS='1' AND ACL_ID=" + aclId;
                executeUpdate(sql);
                sql = "UPDATE ACL_ROWS SET STATUS='1' WHERE ACL_ID=" + aclId;
                executeUpdate(sql);
                throw new SignOnException("Failed to save acl entry for ACL_ID=" + aclId + ", " + e.toString());
            }

            // success, delete old rows, change status of new ones
            sql = "DELETE FROM ACL_ROWS WHERE STATUS='0' AND ACL_ID=" + aclId;
            executeUpdate(sql);
        } catch (SQLException e) {
            throw new SignOnException("Failed to save acl entry for ACL_ID=" + aclName + ", " + e.toString());
        }
    }

    /**
     * Generate the plain text format of an ACL.
     * <pre>
     * user:john:rwx
     * user:john:rwx:doc
     * </pre>
     *
     * @param aclEntries
     * @return List of rows in the plain text file format.
     */
    private static ArrayList<String> aclEntriesToFileRows(List aclEntries) {

        if (aclEntries == null) {
            return null;
        }

        ArrayList<String> l = new ArrayList<String>();
        for (int i = 0; i < aclEntries.size(); i++) {

            Hashtable e = (Hashtable) aclEntries.get(i);
            String eType = (String) e.get("type");
            String eName = (String) e.get("id");
            String ePerms = (String) e.get("perms");
            String aclType = (String) e.get("acltype");

            StringBuffer eRow = new StringBuffer(eType);
            eRow.append(":").append(eName).append(":").append(ePerms);
            if (aclType != null && !aclType.equals("object")) {
                eRow.append(":").append(aclType);
            }

            l.add(eRow.toString());
        }

        return l;
    }

    /**
     *
     * @param aclId
     * @param aclE
     * @throws SQLException
     */
    private void saveAclEntry(String aclId, String aclE) throws SQLException {

        //first colon
        int firstC = aclE.indexOf(":");
        //each aclRow has at least 2 colons
        int secondC = aclE.indexOf(":", firstC + 1);

        //if the type is added into end there is the 3rd colon
        int thirdC = aclE.indexOf(":", secondC + 1);

        String eType = aclE.substring(0, firstC);
        String eName = aclE.substring(firstC + 1, secondC);
        String ePerms;
        String aclType = "object"; //default
        if (thirdC != -1) {
            ePerms = aclE.substring(secondC + 1, thirdC);
            aclType = aclE.substring(thirdC + 1);
        } else {
            ePerms = aclE.substring(secondC + 1);
        }

        //ignore "description" because we hold descriptions in ACL text files only
        if (!eType.equals("description")) {
            String sql = "INSERT INTO ACL_ROWS (ACL_ID, ENTRY_TYPE, TYPE, PRINCIPAL, PERMISSIONS, STATUS) "
                    + " VALUES (" + aclId + ", '" + eType + "','" + aclType + "','" + eName + "','" + ePerms + "', 1)";
            executeUpdate(sql);
        }
    }

    /**
     * Checks if entry already exists.
     *
     * @param aclId acl id
     * @param entryType entry type
     * @param principalType principal type
     * @param principalName principal name
     * @return CSV entry permissions
     */
    private String getEntryPermissions(String aclId, String entryType, String principalType,
            String principalName) throws SQLException {
        //NB type and entry_type are SWITCHED in the DB
        String sql = "SELECT PERMISSIONS FROM ACL_ROWS WHERE ACL_ID = " + aclId + " AND ENTRY_TYPE='" + principalType + "' AND "
                + " TYPE='" + entryType + "' AND PRINCIPAL ='" + principalName + "'";

        String[][] r = executeStringQuery(sql);

        if (r.length > 0) {
            return r[0][0];
        } else {
            return null;
        }

    }

    /**
     * Merges one CSV permissions String with the other avoiding duplicates.
     * Example: Result of merging "a,b,c,d" and "a,x,c,y" is "a,b,c,d,x,y"
     *
     * @param existingPermissions existing permissions
     * @param newPermissions new permissions String
     * @return merged string
     */
    private static String mergePermissions(String existingPermissions, String newPermissions) {
        StringTokenizer oldPerms = new StringTokenizer(existingPermissions, ",");
        StringTokenizer newPerms = new StringTokenizer(newPermissions, ",");

        ArrayList<String> allPerms = new ArrayList<String>();

        while (oldPerms.hasMoreTokens()) {
            allPerms.add(oldPerms.nextToken());
        }

        while (newPerms.hasMoreTokens()) {
            String p = newPerms.nextToken();
            if (!allPerms.contains(p)) {
                allPerms.add(p);
            }
        }
        return StringUtils.join(allPerms, ",");

    }

    @Override
    public void readGroups(HashMap<String, Group> groups, HashMap<String, Principal> users) throws SQLException, SignOnException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void writeGroups(Hashtable<String, Group> groups) throws SignOnException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void readPermissions(HashMap permissions, Hashtable prmDescrs) throws SignOnException {
        throw new UnsupportedOperationException();
    }
}
