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
 * The Original Code is "NaMod project".
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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Database utilities.
 *
 * @author Kaido Laine
 * @version 1.2
 */
public class DatabaseConnection {

    /** Database connection url. */
    private String connectionUrl;

    /** Database driver name. */
    private String driver;

    /**
     * Creates Database Connection container.
     *
     * @param url database connection url
     * @param driver Driver name
     */
    DatabaseConnection(String url, String driver) {
        this.connectionUrl = url;
        this.driver = driver;
    }

    /**
     * Establishes and returns database connection.
     *
     * @param user database username
     * @param password database password
     * @throws SQLException if creating connection fails
     * @return database connection
     */
    public Connection getConnection(String user, String password) throws SQLException {
        //TODO use datasource instead to prevent establishing connection each time.
        try {
            Class.forName(this.driver);
            Connection conn = DriverManager.getConnection(this.connectionUrl, user, password);
            AccessController.dbInError = false;
            return conn;
        } catch (Throwable t) {
            //set global variable to false to make the AccessController to read ACLS from the database until it is fixed
            AccessController.dbInError = true;
            throw new SQLException("Failed to get database connection " + t);
        }
    }

}
