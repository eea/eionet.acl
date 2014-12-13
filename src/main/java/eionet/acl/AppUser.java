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
 */

package eionet.acl;

import eionet.directory.DirServiceException;
import eionet.directory.DirectoryService;

/**
 * Implementation of user class for testing purposes.
 *
 * @author heinljab
 *
 */
public class AppUser {

    /** */
    private static final String PASSWORD_FOR_DEBUGGING = "mi6";

    /** */
    private String _userName = null;

    /** */
    public AppUser()  {
    }

    /**
     *
     * @return
     */
    public String getUserName() {
        return _userName;
    }

    /**
     *
     * @param user
     * @param pwd
     * @throws SignOnException
     */
    public void authenticate(String user, String pwd) throws SignOnException {
        try {

            if (pwd != null && pwd.equals(PASSWORD_FOR_DEBUGGING)) {
                if (user == null)
                    throw new SignOnException("Username not given for debugging password");
                else {
                    _userName = user;
                    return;
                }
            }

            AuthMechanism.sessionLogin(user,pwd);
            _userName = user;
        } catch (SignOnException de) {
            _userName = null;
            throw new SignOnException("Not authenticated");
        }
    }

}
