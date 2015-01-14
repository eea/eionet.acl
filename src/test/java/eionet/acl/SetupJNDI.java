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

    static String subContext = "java:/comp/env/acl/";
    static boolean isSetup = false;
    static boolean isDSSetup = false;

    public static void setUpPlain() throws Exception {
        // Create initial context
        if (isSetup) {
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

        ic.bind(subContext + "file.aclfolder", "target/test-classes");
        ic.bind(subContext + "file.localgroups", "target/test-classes/acl.group");
        ic.bind(subContext + "file.permissions", "target/test-classes/acl.prms");
        ic.bind(subContext + "file.localusers", "target/test-classes/users.xml");
        ic.bind(subContext + "owner.permission", "c");
        ic.bind(subContext + "admin", "true");
        ic.bind(subContext + "authenticated.access", "authenticated");
        ic.bind(subContext + "anonymous.access", "anonymous");
        ic.bind(subContext + "db.driver", "org.h2.Driver");
        ic.bind(subContext + "db.url", "jdbc:h2:mem:acl;MODE=MySQL");
        ic.bind(subContext + "db.user", "acl");
        ic.bind(subContext + "db.pwd", "acl");
        isSetup = true;
    }

    public static void setUpWithDataSource() throws Exception {
        setUpPlain();

        if (isDSSetup) {
            return;
        }
        // Construct DataSource
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:acl;MODE=MySQL");
        dataSource.setUser("acl");
        dataSource.setPassword("acl");

        InitialContext ic = new InitialContext();
        ic.bind(subContext + "db.datasource", dataSource);
        isDSSetup = true;
    }
}
