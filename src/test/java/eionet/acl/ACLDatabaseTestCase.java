package eionet.acl;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Properties;

import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;

import org.apache.log4j.PropertyConfigurator;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Abstract base class for several test cases with H2 memory database.
 *
 * @author Kaido Laine
 */
public abstract class ACLDatabaseTestCase {

    /** connection object. */
    protected static Connection connection;

    /**
     * Initialize the logging system. It is used by dbunit.
     */
    @BeforeClass
    public static void setupLogger() throws Exception {
        Properties logProperties = new Properties();
        logProperties.setProperty("log4j.rootCategory", "DEBUG, CONSOLE");
        logProperties.setProperty("log4j.appender.CONSOLE", "org.apache.log4j.ConsoleAppender");
        logProperties.setProperty("log4j.appender.CONSOLE.Threshold", "ERROR");
        logProperties.setProperty("log4j.appender.CONSOLE.layout", "org.apache.log4j.PatternLayout");
        logProperties.setProperty("log4j.appender.CONSOLE.layout.ConversionPattern", "- %m%n");
        PropertyConfigurator.configure(logProperties);
    }

    /**
     * Initializes H2 database connection and inserts the tables.
     * @throws Exception if initialization fails
     */
    @BeforeClass
    public static void initDatabase() throws Exception {
        JdbcDataSource ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:acl;MODE=MySQL");
        ds.setUser("acl");
        ds.setPassword("acl");
        connection = ds.getConnection();
        Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection));
        Liquibase liquibase = new Liquibase("dbChangeLog.xml", new ClassLoaderResourceAccessor(), database);
        liquibase.update("");
    }

    /**
     * Closes the H2 database connection.
     *
     * @throws SQLException if close does not succeed
     */
    @AfterClass
    public static void closeDatabase() throws SQLException {
        connection.close();
    }

}

