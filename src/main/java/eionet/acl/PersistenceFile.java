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
 * The Original Code is "eionet.acl"
 *
 * The Initial Developer of the Original Code is TietoEnator.
 * The Original Code code was developed for the European
 * Environment Agency (EEA) under the IDA/EINRC framework contract.
 *
 * Copyright (C) 2014 by European Environment Agency.  All
 * Rights Reserved.
 *
 * Original Code: Søren Roug
 */
package eionet.acl;

import java.io.IOException;
import java.io.File;
import java.security.acl.Group;
import java.security.acl.Permission;
import java.security.Principal;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import eionet.acl.impl.AclImpl;
import eionet.acl.impl.PrincipalImpl;
import eionet.propertyplaceholderresolver.CircularReferenceException;
import eionet.propertyplaceholderresolver.ConfigurationPropertyResolver;
import eionet.propertyplaceholderresolver.UnresolvedPropertyException;
import java.util.logging.Level;

import org.apache.log4j.Logger;

/**
 * File operations implementation.
 */
public class PersistenceFile implements Persistence {

    /**
     * logger instance.
     */
    private static final Logger LOGGER = Logger.getLogger(PersistenceFile.class);

    /**
     * Folder where ACL files reside.
     */
    private String aclsFolderName;

    /**
     * File name for local groups.
     */
    private String localgroupsFileName;

    /**
     * File name for permissions.
     */
    private String permissionsFileName;

    /**
     * ACL files reader.
     */
    private AclFileReader fileReader;

    /**
     * Constructor.
     */
    public PersistenceFile(ConfigurationPropertyResolver configurationPropertyResolver) {
        try {
            permissionsFileName = configurationPropertyResolver.resolveValue("file.permissions");
            localgroupsFileName = configurationPropertyResolver.resolveValue("file.localgroups");
            aclsFolderName = configurationPropertyResolver.resolveValue("file.aclfolder");

            try {
                AclInitializerImpl aclInitializer = new AclInitializerImpl("acl", configurationPropertyResolver);
                aclInitializer.execute();
            } catch (Exception ex) {
                java.util.logging.Logger.getLogger(AccessController.class.getName()).severe(ex.getMessage());
            }
            fileReader = new AclFileReader();
        } catch (UnresolvedPropertyException ex) {
            java.util.logging.Logger.getLogger(PersistenceFile.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CircularReferenceException ex) {
            java.util.logging.Logger.getLogger(PersistenceFile.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Read permissions from the files.
     *
     * @throws SignOnException if reading fails
     */
    @Override
    public void readPermissions(HashMap<String, Permission> permissions, Hashtable<String, String> prmDescrs)
            throws SignOnException {
        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(permissionsFileName)) {
                XmlFileReaderWriter.readPermissions(permissionsFileName, permissions, prmDescrs);
            } else {
                fileReader.readPermissions(permissionsFileName, permissions, prmDescrs);
            }
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException) {
                throw new SignOnException(e, "No such file: " + localgroupsFileName);
            } else {
                throw new SignOnException(e, "I/O error reading file: " + localgroupsFileName);
            }
        }
    }

    /**
     * Read local groups from the files.
     *
     */
    @Override
    public void readGroups(HashMap<String, Group> groups, HashMap<String, Principal> users) throws SQLException, SignOnException {
        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(localgroupsFileName)) {
                XmlFileReaderWriter.readGroups(localgroupsFileName, groups, users);
            } else {
                fileReader.readGroups(localgroupsFileName, groups, users);
            }
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException) {
                throw new SignOnException(e, "No such file: " + localgroupsFileName);
            } else {
                throw new SignOnException(e, "I/O error reading file: " + localgroupsFileName);
            }
        }
    }

    /**
     * Write local groups to file.
     */
    @Override
    public void writeGroups(Hashtable<String, Group> groups) throws SignOnException {
        XmlFileReaderWriter.writeGroups(localgroupsFileName, groups);
    }

    /**
     * Read the ACL files from the designated folder.
     *
     * @param acls - a hashmap to be filled by the method.
     */
    @Override
    public void initAcls(HashMap<String, AccessControlListIF> acls) throws SignOnException {
        // read acl files
        File[] aclFiles = fileReader.getAclFiles(aclsFolderName);
        for (int i = 0; i < aclFiles.length; i++) {
            String name = getAclName(aclFiles[i]);
            AccessControlListIF acl = readAclFile(aclFiles[i]);

            name = name.replace('_', '/');

            acls.put(name, acl);
        }
    }

    /**
     * Get the name of the ACL from the file name it is stored in.
     *
     * @param aclFile - file name of acl file.
     * @return the name of the ACL
     */
    private String getAclName(File aclFile) {
        String fileName = aclFile.getName();
        int pos = fileName.indexOf(".acl");

        return fileName.substring(0, pos);
    }

    /**
     * Reads an ACL. Due to the spaghetti structure of the original code, this
     * won't work unless AccessController has been initialised.
     *
     * @param aclName - the name of the ACL. e.g. "/groups"
     * @return access control list.
     */
    AccessControlList readAcl(String aclName) throws SignOnException {
        File aclFile = new File(aclsFolderName, aclName.replace('/', '_') + ".acl");
        return readAclFile(aclFile);
    }

    /**
     * Read an ACL.
     *
     * @param aclFile - file name to read from.
     * @return access control list.
     */
    private AccessControlList readAclFile(File aclFile) throws SignOnException {

        AccessControlList acl = new AccessControlList(this);
        acl.setMechanism(AccessControlListIF.TEXT_FILE);

        String name = getAclName(aclFile);

        acl.name = name.replace('_', '/');

        //!!description cannot be null
        acl.description = acl.name;

        String aclFileName = aclFile.getAbsolutePath();

        //1st we set a fake owner, text file based ACL's do not have
        //one special owner specified
        acl.owner = new PrincipalImpl(acl.name);

        acl.acl = new AclImpl(acl.owner, acl.name);
        readAclFromFile(acl, aclFileName);
        return acl;
    }

    /**
     * Read the ACL from a file. The format can be in XML or plain text.
     *
     * @throws SignOnException
     */
    private void readAclFromFile(AccessControlList acl, String aclFileName) throws SignOnException {

        AclFileReader fReader = new AclFileReader();
        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(aclFileName)) {
                XmlFileReaderWriter.readACL(aclFileName, acl);
            } else {
                ArrayList<String> aRows = fReader.readFileRows(aclFileName);
                acl.processAclRows(aRows);
            }
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException) {
                throw new SignOnException(e, "No such file: " + aclFileName);
            } else {
                throw new SignOnException(e, "I/O error reading file: " + aclFileName);
            }
        }
    }

    @Override
    public void addAcl(String aclPath, String owner, String description, boolean isFolder)
            throws SQLException, SignOnException {
        throw new SignOnException("Method is not supported");
    }

    @Override
    public void addAcl(String aclPath, String owner, String description) throws SQLException, SignOnException {
        throw new SignOnException("Method is not supported");
    }

    @Override
    public void writeAcl(String aclName, Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
        File aclFile = new File(aclsFolderName, aclName.replace('/', '_') + ".acl");
        XmlFileReaderWriter.writeACL(aclFile.getPath(), aclAttrs, aclEntries);
    }

    @Override
    public void removeAcl(String aclPath) throws SQLException, SignOnException {
        throw new SignOnException("This ACL cannot be removed by this method.");
    }

    @Override
    public void renameAcl(String currentAclPath, String newAclPath) throws SQLException, SignOnException {
        throw new SignOnException("Method is not supported");
    }

}
