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

import java.io.IOException;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;


/**
 * File operations implementation.
 */
public class FileModule {

    /** logger instance. */
    private static final Logger LOGGER = Logger.getLogger(FileModule.class);

    /** Folder where ACL files reside. */
    private String aclsFolderName;

    /** File name for local groups. */
    private String localgroupsFileName;

    /** File name for permissions. */
    private String permissionsFileName;

    /** ACL files reader. */
    private AclFileReader fileReader;


    private ResourceBundle props = null;

    public FileModule(ResourceBundle props) {
        this.props = props;
        permissionsFileName = props.getString("application.permissions.file");
        localgroupsFileName = props.getString("application.localgroups.file");
        aclsFolderName = props.getString("application.acl.folder");

        fileReader = new AclFileReader();
    }

    /**
     * Read permissions from the files.
     *
     * @throws SignOnException if reading fails
     */
    public void readPermissions(HashMap permissions, Hashtable prmDescrs) throws SignOnException {
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
     * Read local groups from the files.
     *
     * @throws SignOnException if reading fails
     */
    public void readGroups(HashMap groups, HashMap users) throws SignOnException {
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
     * Write local groups to file.
     */
    public void writeGroups(Hashtable groups) throws SignOnException {
        XmlFileReaderWriter.writeGroups(localgroupsFileName, groups);
    }

    /**
     * Read the ACL files from the designated folder.
     *
     * @param acls - a hashmap to be filled by the method.
     */
    public void initAcls(HashMap<String, AccessControlListIF> acls) throws SignOnException {
        // read acl files
        File[] aclFiles = fileReader.getAclFiles(aclsFolderName);
        for (int i = 0; i < aclFiles.length; i++) {
            String name = fileReader.getAclName(aclFiles[i]);
            AccessControlListIF acl = new AccessControlListFromFile(aclFiles[i]);
            
            name = name.replace('_', '/');
            
            acls.put(name, acl);
        }   
    }

    /*
    void writeAcl(String aclName, Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
      // Need to encapsulate aclFileName
      //XmlFileReaderWriter.writeACL(aclFileName, aclAttrs, aclEntries);
    }
    */


}
