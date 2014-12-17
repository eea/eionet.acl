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
 */
class AccessControlListFromFile extends AccessControlList {

    /** The filename containing the ACL. */
    private String aclFileName;

    private AclFileReader fReader;

    private static final Logger LOGGER = Logger.getLogger(AccessControlListFromFile.class);

    /**
     * Construct ACL from contents of file.
     *
     * @param aclFile - The file containing the access control list.
     */
    AccessControlListFromFile(File aclFile) throws SignOnException {
        super();

        setMechanism(TEXT_FILE);
        fReader = new AclFileReader();
        name = fReader.getAclName(aclFile);

        name = name.replace('_', '/');

        //!!description cannot be null
        description = name;

        aclFileName = aclFile.getAbsolutePath();

        //1st we set a fake owner, text file based ACL's do not have
        //one special owner specified
        owner = new PrincipalImpl(name);

        acl = new AclImpl(owner, name);
        readAclFromFile();
    }

    /**
     * Read the ACL from a file. The format can be in XML or plain text.
     *
     * @throws SignOnException
     */
    private void readAclFromFile() throws SignOnException {

        try {
            if (XmlFileReaderWriter.isXmlFileWannabe(aclFileName))
                XmlFileReaderWriter.readACL(aclFileName, this);
            else {
                ArrayList aRows = fReader.readFileRows(aclFileName);
                processAclRows(aRows);
            }
        } catch (IOException e) {
            if (e instanceof java.io.FileNotFoundException)
                throw new SignOnException(e, "No such file: " + aclFileName);
            else
                throw new SignOnException(e, "I/O error reading file: " + aclFileName);
        }
    }


    @Override
    public void setAcl(Map<String, String> aclAttrs, List aclEntries) throws SignOnException {
        LOGGER.debug("setAcl()");
        XmlFileReaderWriter.writeACL(aclFileName, aclAttrs, aclEntries);
    }

}
