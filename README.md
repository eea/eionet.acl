ACL Module 2.0
==============

This is a module that implements an Access Control Mechanism based on Distributed Computing Environment.

Version 2.0 has the same public interface as version 1.x except the package name space is changed from `com.tee.uit.security` to `eionet.acl`.

Another change, but one that has requires no change in code is that the eionet acl-impl library has been included. This contains the SUN Microsystems implementation of groups, users etc. The only effect is that you _might_ have to remove the following in your pom.xml.
```xml
<dependency>
    <groupId>eionet.acl</groupId>
    <artifactId>acl-impl</artifactId>
    <version>1.0</version>
</dependency>
```

There is also a change in the way the library is configured.

1. It uses acl.properties instead of uit.properties.
2. All properties starting with `acl.` or `application.` have lost that prefix, as all properties in the file are relevant to ACL only. Additionally, there are a few other changes.

Here are the changes:
| Version 1 | Version 2 |
| --------- | --------- |
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
        <version>2.0</version>
    </dependency>
</dependencies>
```


Configuration
-------------
- Create the ACL database tables - edit your project's Liquibase change log file and add the change sets from the dbChangeLog.xml.

- Copy `*.acl, acl.group, acl.prms` and `users.xml` from `src/test/resources` to external folder and make the necessary editing.

The package can be configured via JNDI or a properties file. If a environment entry in JNDI is found the all required entries must be configured via JNDI. You configure the appliaction through JNDI with the META-INF/context.xml of the web application using this package. In Tomcat all JNDI names will automatically be prefixed with `java:/comp/env`
```xml
<Context>
    <Environment name="acl/acl.owner.permission" value="c" type="java.lang.String" override="false"/>
    <Environment name="acl/db.driver" value="org.h2.Driver" type="java.lang.String" override="false"/>
</Context>
```
Instead of using db.driver, db.url to set up the connection to the database it is also possible to use a acl/datasource.

```xml
<Context>
    <Resource name="acl/acl.datasource"
        auth="Container"
        type="javax.sql.DataSource"
        maxActive="100"
...
</Context>
```

Alternatively copy `uit.properties` from `src/test/resources` to your project's classpath and change the property values accordingly. Note that the file and folder paths in the `uit.properties` are relative because of unit tests. For other usage, absolute paths should be used.


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
