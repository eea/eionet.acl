ACL Module 4.0
=======================

This is a module that implements an Access Control Mechanism based on Distributed Computing Environment.


Another change, but one that has requires no change in code is that the eionet acl-impl library has been included. This contains the SUN Microsystems implementation of groups, users etc. 

In version 4.0 there is a change in the way the library is configured. The AccessController needs an AclProperties object for initialisation. There is a class AclPropertiesBuilder that can create an AclProperties object from a property file in the format of the 3.1 version.

There is a new property that can be set, initial.admin, that overrides the admins of the gdem.group if set. The initial.admin accepts comma seperated names, e.g. initial.admin=roug,katsanas will override the admins in the files, for easier bootstraping.

Here are the changes:

| Version 1.0 and 2.0          | Version 4.0 |
| -------------------          | ----------- |
| acl.owner.permission         | owner.permission |
| acl.anonymous.access         | anonymous.access |
| acl.authenticated.access     | authenticated.access |
| acl.defaultdoc.permissions   | defaultdoc.permissions |
| acl.persistence.provider     | persistence.provider |
| acl.localusers.xml           | file.localusers |
| application.permissions.file | file.permissions |
| application.localgroups.file | file.localgroups |
| application.acl.folder       | file.aclfolder |
| db.url                       | db.url |
| db.driver                    | db.driver |
| db.user                      | db.user |
| db.pwd                       | db.pwd |
| -                            | initial.admin

In spring applications you can configure the module using spring beans. For example :

    <bean id="aclProperties" class="eionet.acl.AclProperties">
        <property name="ownerPermission" value="${owner.permission}" />
        <property name="anonymousAccess" value="${anonymous.access}" />
        <property name="authenticatedAccess" value="${authenticated.access}" />
        <property name="defaultdocPermissions" value="${defaultdoc.permissions}" />
        ......more properties......
    </bean>
    <bean id="accessController" class="eionet.acl.AccessController">
        <constructor-arg index="0" ref="aclProperties" />
    </bean>

Installation
------------
This package is built with Maven, and is deployed to the agency repository.
```
$ mvn deploy
```

Add this to your pom.xml:
```xml
<repositories>
    <repository>
        <id>eea</id>
        <name>EEA Release Repository</name>
        <url>http://archiva.eionet.europa.eu/repository/internal</url>
        <snapshots>
            <enabled>false</enabled>
        </snapshots>
    </repository>
</repositories>
...
<dependencies>
    <dependency>
        <groupId>eionet</groupId>
        <artifactId>acl</artifactId>
        <version>4.0-SNAPSHOT</version>
    </dependency>
</dependencies>
```


Configuration
-------------
- Create the ACL database tables - edit your project's Liquibase change log file and add the change sets from the dbChangeLog.xml.

- Copy `*.acl, acl.group, acl.prms` and `users.xml` from `src/test/resources` to external folder and make the necessary editing.

Alternatively copy `acl.properties` from `src/test/resources` to your project's classpath and change the property values accordingly. Note that the file and folder paths in the `acl.properties` are relative because of unit tests. For other usage, absolute paths should be used.

Unit tests
----------
All the sources for unit tests are in src/test/java and src/test/resources.

As configured in AccessControlListTest.java and acl.properties, the database tests are run on H2 in-memory database. The database structure is located in dbChangeLog.xml which is the change log file for Liquibase. Because MySql and H2 databases differ a little, there are modifications to SQL so it would work on both of the databases.

How to use it
-------------
The main interface to the ACL library is to check whether a user has a type of access to an object. These objects are arranged in a tree-like structure like the local part of a URL.

```java
boolean access = AccessController.hasPermission("kaido", "/contracts/sa55727" , "r");
```

TODO
----
The concept of ownership is broken. The file-based ACLs don't support it at all, and the database ACLs don't support change of ownership. Additionally, the ownership is for the protected object _and_ the ACL. In some cases, the ownership is stored in the protected object, and there should be an API the application can use to declare that the user checking permission 'x' is also the owner of the object.

Releasing new versions
----------------------
While developing a new version, add *-SNAPSHOT* to the upcoming version id in pom.xml. When you are satisfied with the result, remove the the *-SNAPSHOT* part, and commit. Then you tag the release, deploy it, increase the minor number and append *-SNAPSHOT* again.
```sh
git tag -a v3.1 -m "Version 3.1"
git push origin v3.1
mvn deploy
# Increase to 3.2-SNAPSHOT in pom.xml
git commit pom.xml
```
