ACL Module 2.0
==============

This is a module that implements an Access Control Mechanism based on Distributed Computing Environment.

Installation and usage:
-----------------------
This package is built with Maven, and is deployed to the agency repository.
```
$ mvn deploy
```

Add this to your pom.xml:
```
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

```


Configuration:
--------------
- Create the ACL database tables - edit your project's Liquibase change log file and add the change sets from the dbChangeLog.xml.

- Copy `*.acl, acl.group, acl.prms` and `users.xml` from `src/test/resources` to external folder and make the necessary editing.

- Copy `uit.properties` from `src/test/resources` to your project's classpath and change the property values accordingly.
  Note that the file and folder paths in the `uit.properties` are relative because of unit tests. For other usage, absolute paths should be used.


Unit tests:
-----------
All the sources for unit tests are in src/test/java and src/test/resources.

As configured in AccessControlListTest.java and uit.properties, the database tests are run on H2 in-memory database. The database structure
is located in dbChangeLog.xml which is the change log file for Liquibase. Because MySql and H2 databases differ a little, there are modifications
to SQL so it would work on both of the databases.
