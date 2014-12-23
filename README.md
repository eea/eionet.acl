ACL Module 2.0
==============

This is a module that implements an Access Control Mechanism based on Distributed Computing Environment.

Version 2.0 has the same public interface as version 1.x except the package name space is changed from com.tee.uit.security to eionet.acl.

Another change, but one that has requires no change in code is that the eionet acl-impl library has been included. This contains the SUN Microsystems implementation of groups, users etc. The only effect is that you _might_ have to remove the following in your pom.xml.
```xml
<dependency>
    <groupId>eionet.acl</groupId>
    <artifactId>acl-impl</artifactId>
    <version>1.0</version>
</dependency>
```

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
        <groupId>eionet.acl</groupId>
        <artifactId>acl</artifactId>
        <version>2.0</version>
    </dependency>
</dependencies>
```


Configuration
-------------
- Create the ACL database tables - edit your project's Liquibase change log file and add the change sets from the dbChangeLog.xml.

- Copy `*.acl, acl.group, acl.prms` and `users.xml` from `src/test/resources` to external folder and make the necessary editing.

- Copy `uit.properties` from `src/test/resources` to your project's classpath and change the property values accordingly.
  Note that the file and folder paths in the `uit.properties` are relative because of unit tests. For other usage, absolute paths should be used.


Unit tests
----------
All the sources for unit tests are in src/test/java and src/test/resources.

As configured in AccessControlListTest.java and uit.properties, the database tests are run on H2 in-memory database. The database structure
is located in dbChangeLog.xml which is the change log file for Liquibase. Because MySql and H2 databases differ a little, there are modifications
to SQL so it would work on both of the databases.

How to use it
-------------

The main interface to the ACL library is to check whether a user has a type of access to an object. These objects are arranged in a tree-like structure like the local part of a URL.

```java
boolean access = AccessController.hasPermission("kaido", "/contracts/sa55727" , "r");
```

TODO
----
The concept of ownership is broken. The file-based ACLs don't support it at all, and the database ACLs don't support change of ownership. Additionally, the ownership is for the protected object _and_ the ACL. In some cases, the ownership is stored in the protected object, and there should be an API the application can use to declare that the user checking permission 'x' is also the owner of the object.
