package eionet.acl.impl;

/*
 * Copyright 1996-2006 Sun Microsystems, Inc.  All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Sun designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Sun in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 */

import java.security.Principal;
import eionet.acl.AclEntry;
import eionet.acl.Group;
import eionet.acl.Permission;
import java.util.Enumeration;
import java.util.Vector;

/**
 * This is a class that describes one entry that associates users
 * or groups with permissions in the ACL.
 * The entry may be used as a way of granting or denying permissions.
 * @author      Satish Dharmaraj
 */
public class AclEntryImpl implements AclEntry {
    private Principal user = null;
    private Vector<Permission> permissionSet = new Vector<Permission>(10, 10);
    private boolean negative = false;

    /**
     * Construct an ACL entry that associates a user with permissions
     * in the ACL.
     * @param user The user that is associated with this entry.
     */
    public AclEntryImpl(Principal user) {
        this.user = user;
    }

    /**
     * Construct a null ACL entry
     */
    public AclEntryImpl() {
    }

    /**
     * Sets the principal in the entity. If a group or a
     * principal had already been set, a false value is
     * returned, otherwise a true value is returned.
     * @param user The user that is associated with this entry.
     * @return true if the principal is set, false if there is
     * one already.
     */
    @Override
    public boolean setPrincipal(Principal user) {
        if (this.user != null)
          return false;
        this.user = user;
        return true;
    }

    /**
     * This method sets the ACL to have negative permissions.
     * That is the user or group is denied the permission set
     * specified in the entry.
     */
    @Override
    public void setNegativePermissions() {
        negative = true;
    }

    /**
     * Returns true if this is a negative ACL.
     */
    @Override
    public boolean isNegative() {
        return negative;
    }

    /**
     * A principal or a group can be associated with multiple
     * permissions. This method adds a permission to the ACL entry.
     * @param permission The permission to be associated with
     * the principal or the group in the entry.
     * @return true if the permission was added, false if the
     * permission was already part of the permission set.
     */
    @Override
    public boolean addPermission(Permission permission) {

        if (permissionSet.contains(permission))
          return false;

        permissionSet.addElement(permission);

        return true;
    }

    /**
     * The method disassociates the permission from the Principal
     * or the Group in this ACL entry.
     * @param permission The permission to be disassociated with
     * the principal or the group in the entry.
     * @return true if the permission is removed, false if the
     * permission is not part of the permission set.
     */
    @Override
    public boolean removePermission(Permission permission) {
        return permissionSet.removeElement(permission);
    }

    /**
     * Checks if the passed permission is part of the allowed
     * permission set in this entry.
     * @param permission The permission that has to be part of
     * the permission set in the entry.
     * @return true if the permission passed is part of the
     * permission set in the entry, false otherwise.
     */
    @Override
    public boolean checkPermission(Permission permission) {
        return permissionSet.contains(permission);
    }

    /**
     * return an enumeration of the permissions in this ACL entry.
     */
    @Override
    public Enumeration<Permission> permissions() {
        return permissionSet.elements();
    }

    /**
     * Return a string representation of  the contents of the ACL entry.
     */
    @Override
    public String toString() {
        StringBuffer s = new StringBuffer();
        if (negative)
          s.append("-");
        else
          s.append("+");
        if (user instanceof Group)
            s.append("Group.");
        else
            s.append("User.");
        s.append(user + "=");
        Enumeration<Permission> e = permissions();
        while(e.hasMoreElements()) {
            Permission p = e.nextElement();
            s.append(p);
            if (e.hasMoreElements())
                s.append(",");
        }
        return new String(s);
    }

    /**
     * Clones an AclEntry.
     */
    @Override
    public synchronized Object clone() {
        AclEntryImpl cloned;
        cloned = new AclEntryImpl(user);
        cloned.permissionSet = (Vector<Permission>) permissionSet.clone();
        cloned.negative = negative;
        return cloned;
    }

    /**
     * Return the Principal associated in this ACL entry.
     * The method returns null if the entry uses a group
     * instead of a principal.
     */
    @Override
    public Principal getPrincipal() {
        return user;
    }
}