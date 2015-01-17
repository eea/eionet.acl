package eionet.acl;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import org.junit.BeforeClass;
import org.junit.Test;
import org.h2.jdbcx.JdbcDataSource;

public class SetupJNDI {

    static String aclContextLocation = "java:/comp/env/acl/";
    static boolean isSetupCore = false;
    static boolean isSetupPlain = false;
    static boolean isSetupDS = false;

    public static void setUpCore() throws Exception {
        if (isSetupCore) {
            return;
        }
        System.setProperty(Context.INITIAL_CONTEXT_FACTORY, "org.apache.naming.java.javaURLContextFactory");
        System.setProperty(Context.URL_PKG_PREFIXES, "org.apache.naming");
        InitialContext ic = new InitialContext();

        ic.createSubcontext("java:");
        ic.createSubcontext("java:/comp");
        ic.createSubcontext("java:/comp/env");
        ic.createSubcontext("java:/comp/env/jdbc");
        ic.createSubcontext("java:/comp/env/acl");
        isSetupCore = true;
    }

    public static void setUpPlain() throws Exception {
        if (isSetupPlain) {
            return;
        }
        setUpCore();
        InitialContext ic = new InitialContext();
        ic.bind(aclContextLocation + "file.aclfolder", "target/test-classes");
        ic.bind(aclContextLocation + "file.localgroups", "target/test-classes/acl.group");
        ic.bind(aclContextLocation + "file.permissions", "target/test-classes/acl.prms");
        ic.bind(aclContextLocation + "file.localusers", "target/test-classes/users.xml");
        ic.bind(aclContextLocation + "owner.permission", "c");
        ic.bind(aclContextLocation + "admin", "true");
        ic.bind(aclContextLocation + "authenticated.access", "authenticated");
        ic.bind(aclContextLocation + "anonymous.access", "anonymous");
        ic.bind(aclContextLocation + "db.driver", "org.h2.Driver");
        ic.bind(aclContextLocation + "db.url", "jdbc:h2:mem:acl;MODE=MySQL");
        ic.bind(aclContextLocation + "db.user", "acl");
        ic.bind(aclContextLocation + "db.pwd", "acl");
        isSetupPlain = true;
    }

    public static void setUpWithDataSource() throws Exception {
        setUpCore();
        setUpPlain();

        if (isSetupDS) {
            return;
        }
        // Construct DataSource
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:acl;MODE=MySQL");
        dataSource.setUser("acl");
        dataSource.setPassword("acl");

        InitialContext ic = new InitialContext();
        ic.bind(aclContextLocation + "db.datasource", dataSource);
        isSetupDS = true;
    }

    public static void setUpWithPropFile(String filename) throws Exception {
        setUpCore();
        InitialContext ic = new InitialContext();
        ic.bind(aclContextLocation + "propertiesfile", "target/test-classes/" + filename);
    }

}
