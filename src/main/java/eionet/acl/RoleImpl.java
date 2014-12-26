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

import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

import eionet.acl.impl.PrincipalImpl;
import eionet.directory.DirServiceException;
import eionet.directory.DirectoryService;

/**
 * Class to hold Eionet roles.
 */
class RoleImpl implements Group {

    private String _name;
    private Hashtable<String, Principal> _members;


    public RoleImpl(String roleName) {
        _name = roleName;
        initMembers();
    }

    private void initMembers() {
        if (_members == null)
          _members = new Hashtable<String, Principal>();

        try {
            Vector occupants = DirectoryService.getOccupants(_name);

            if (occupants == null)
                return;

            //System.out.println("******** occupants " + occupants);

            for (Iterator i = occupants.iterator(); i.hasNext();) {
                String userName = (String) i.next();
                Principal member = new PrincipalImpl(userName);

                addMember(member);
            }

        } catch (DirServiceException dire) {
          //do nothing, there will be no users under this role
        } catch (Exception e) {
          System.out.println("******** " + e.toString());
        }

    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public String getName() {
        return _name;
    }

    @Override
    public boolean isMember(Principal user) {
        boolean b = false;

        if (_members.containsKey(user.getName()))
            b = true;
        return b;

    }

    @Override
    public boolean addMember(Principal user) {
        if (isMember(user))
            return false;
        else {
            _members.put(user.getName(), user);
            return true;
        }
    }

    @Override
    public boolean removeMember(Principal user) {
        if (!isMember(user))
            return false;
        else {
            _members.remove(user);
            return true;
        }
    }

    @Override
    public Enumeration<? extends Principal> members() {
        //_members.entrySet().iterator().
        return _members.elements();
    }

}
