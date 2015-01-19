package eionet.acl;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.h2.jdbcx.JdbcDataSource;

public class TomcatJNDITest {

    @Before
    public void setUp() throws Exception {
        SetupJNDI.setUpWithDataSource();
    }

    @Test
    public void initialContextWithDS() throws Exception {
        Context ctx = new InitialContext();
        DataSource ref = (DataSource) ctx.lookup("java:comp/env/acl/db.datasource");
        assertTrue(ref.toString().contains("url=jdbc:h2:mem:acl;MODE=MySQL"));
    }

    @Test
    public void simpleStringLookup() throws Exception {
        Context ctx = new InitialContext();
        String ref = (String) ctx.lookup("java:comp/env/acl/owner.permission");
        assertEquals("c", ref);
    }
}
