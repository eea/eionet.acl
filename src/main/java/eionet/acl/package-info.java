/**
Access Control List mechanism.
<p>
The ACL is derived from principles in the Distributed Computing Environment.
</p>
<p>
Example of an ACL called "/datasets/cdda"
</p>
<pre>
localgroup:dd_admin:d
user:heinlaid:c
owner::w,d,c
authenticated::v
anonymous::
</pre>

All the users belonging to the dd_admin group can delete (d) the dataset and so can the owner of the dataset.
Anyone who is authenticated can view the dataset (v), while anonymous users can't.

<h2>Usage</h2>
The main interface to the ACL library is to check whether a user has a type of access to an object. These objects are arranged in a tree-like structure like the local part of a URL.

<pre>
boolean access = AccessController.hasPermission("kaido", "/contracts/sa55727" , "r");
</pre>

<h2>Default Object Creation (DOC) ACLs</h2>

If an ACL has acl_type "DOC" it is not handled when checking user permissions.
If an ACL is created under this ACL, entry rows with type "DOC" in the parent ACL are admitted to the newly created one.

<h3>Example</h3> 
If there is an ACL called "/datasets"
<pre>
localgroup:dd_admin:i
user:heinlaid:c
owner::w,d,c:doc
authenticated::v:doc
</pre>
All the users belonging to the dd_admin group can create a new dataset (a record in the table)
If a new dataset is created, also a new ACL is created. There is a method in ACL-mechanism API:

<pre>
addAcl(aclPath, owner, description);
</pre>

If a user (for example with username "stefan" creates a dataset with ID=345 the application calls the ACL mechanism API:
<pre>
AccessController.addAcl("/datasets/345", "stefan", "");
</pre>
Now a new ACL ("datasets/345") is added to the ACL hierarchy with those ACL entry rows:

<pre>
owner::w,d,c
authenticated::v
</pre>

Those are copied from the "DOC" type ACL rows in the higher ACL. The word "owner" is a special token, which refers to the username who is the owner of the object. This username is stored elsewhere, and there can exist a method to change the ownership.

<h2>Default Container Creation (DCC) ACLs</h2>

DCC ACLs are used when the system operates with folder-like structures. The main difference is that 
because folders can contain other object - both folders and files - then the <strong>DOC</strong> 
and the <strong>DCC</strong> records are copied to the new folder object. These are to be used when 
a folder or a file is created under the new folder.  

If there is an ACL called "/projects"
<pre>
localgroup:admin:i
user:heinlaid:c
owner::w,d,c:doc
authenticated::v:doc
owner::w,d,c,x:dcc
authenticated::v,x:dcc
</pre>

All the users belonging to the <em>admin</em> group can create a new project (a record in the table)
If the user called 'john' creates a new project called <em>toolx</em>, and a project is a folder, which can contain files and/or folders, then the ACL for "/projects/toolx" becomes:

<pre>
owner::w,d,c,x
authenticated::v,x
owner::w,d,c:doc
authenticated::v:doc
owner::w,d,c,x:dcc
authenticated::v,x:dcc
</pre>

If a hypothetical system uses ACLs and has a folder concept, but it can't have folders inside folders, 
then the <strong>DCC</strong> part should not be copied to the newly created folder.

There is another method in the API to describe whether you are creating a folder or an object.
<pre>
addAcl(aclPath, owner, description, isFolder);
</pre>

 */
package eionet.acl;
