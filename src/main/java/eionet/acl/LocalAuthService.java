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

import org.xml.sax.SAXException;

import java.io.FileNotFoundException;
import org.w3c.dom.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Authentication of local users. These are stored in an XML file containing
 * the user id, password and full name.
 *
 * @author heinljab
 *
 */
public class LocalAuthService {

    /** */
    Document doc;
    boolean supported = false;

    /**
     *
     * @throws SignOnException
     */
    LocalAuthService() throws SignOnException {
        if (doc == null)
            initDoc();
    }

    /**
     *
     * @throws SignOnException
     */
    private void initDoc() throws SignOnException {

        String fileFullPath = null;
        try {
            fileFullPath = (String) AccessController.getAclProperties().getFileLocalusers();
        } catch (Exception mre) {
            supported = false;
            return;
        }

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            doc = db.parse(fileFullPath);
            supported = true;
        } catch (FileNotFoundException fie) {
            fie.printStackTrace();
            throw new SignOnException (fie, "File not found: " + fileFullPath);
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new SignOnException (ioe, "I/O error when reading file: " + fileFullPath);
        } catch (SAXException sae) {
            sae.printStackTrace();
            throw new SignOnException (sae, "SAX error when parsing file: " + fileFullPath);
        } catch (ParserConfigurationException pce) {
            pce.printStackTrace();
            throw new SignOnException (pce, "Parser configuration problem when reading file: " + fileFullPath);
        }
    }

    /**
     * Authenticate.
     */
    public void sessionLogin(String user, String pwd) throws UserNotFoundException, SignOnException {
        /*if (doc == null)
         initDoc(); */

        NodeList  nl = doc.getElementsByTagName("local-users").item(0).getChildNodes();
        boolean authenticated = false;
        for (int i = 0; i < nl.getLength(); i++) {
            //authenticate
            if ( nl.item(i).getNodeType() == nl.item(i).ELEMENT_NODE && nl.item(i).getNodeName().equals("user")
                    && nl.item(i).getAttributes().getNamedItem("username").getNodeValue().equals(user) ) {

                if ( ! nl.item(i).getAttributes().getNamedItem("password").getNodeValue().equals(pwd) )
                    throw new SignOnException("authentication failed, password incorrect");
                else
                    authenticated = true;

            }

        }

        if (!authenticated)
            throw new UserNotFoundException("authentication failed, no such user");
    }

    /**
     * Get the user's full name.
     *
     * @param userName - the user id.
     * @return the full name as a string.
     */
    public String getFullName(String userName) throws SignOnException {
        /*
         if (doc == null)
         initDoc();
         */

        String fullName = null;
        NodeList  nl = doc.getElementsByTagName("local-users").item(0).getChildNodes();
        for (int i = 0; i< nl.getLength(); i++) {
            //authenticate
            if ( nl.item(i).getNodeType() == nl.item(i).ELEMENT_NODE && nl.item(i).getNodeName().equals("user")
                    && nl.item(i).getAttributes().getNamedItem("username").getNodeValue().equals(userName) )

                if (nl.item(i).getAttributes().getNamedItem("fullname") != null)
                    fullName = nl.item(i).getAttributes().getNamedItem("fullname").getNodeValue().trim();
                else
                    fullName = userName;



        }
        /*
         if (fullName == null)
         fullName = userName;
         */
        return fullName;
    }

}
