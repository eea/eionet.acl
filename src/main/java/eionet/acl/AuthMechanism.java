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

import java.io.FileNotFoundException;
import eionet.directory.DirectoryService;
import eionet.directory.DirServiceException;

/**
 * Container that holds all authentication mechanisms.
 */
public class AuthMechanism {

    /** */
    static LocalAuthService localM;

    /**
     *
     */
    public AuthMechanism()  {
    }

    /**
     * Authentication method
     * Depending on which mechanisms are supported logs the user in
     * 1st check the local mechanism, if the user is not listed,
     * 2nd use LDAP, if not responding, tries LDAP backup server
     */
    public static void sessionLogin(String user, String pwd) throws SignOnException {

        boolean authenticated = false;

        if (localM == null)
            localM = new LocalAuthService();

        // try local users
        if (localM.supported) {
            try {
                localM.sessionLogin(user,pwd);
                authenticated = true;
            } catch (UserNotFoundException unfe) {
                authenticated = false;
            } catch (SignOnException soe) {
                throw new SignOnException("Error login to local mechanism:" + soe.toString()) ;
            }
        }

        // if did not get authenticated by local users, try directory
        if (!authenticated) {
            try {
                DirectoryService.sessionLogin(user, pwd);
            } catch (DirServiceException dire) {
                throw new SignOnException("Error login to directory" + dire.toString());
            }
        }
    }

    /**
     * Returns the full name of the user
     */
    public static String getFullName(String userName) throws SignOnException {

        String fullName="";
        if (localM == null)
            localM = new LocalAuthService();

        //try localservice
        if (localM.supported)
            fullName = localM.getFullName(userName);

        if (fullName == null || !localM.supported) {
            try {
                fullName=DirectoryService.getFullName(userName);
            } catch (DirServiceException dire) {
                fullName = userName;
            }
        }

        return fullName;
    }
}
