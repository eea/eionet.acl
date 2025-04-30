package eionet.acl;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 *
 * @author Aris Katsanas <aka@eworx.gr>
 */
public final class AclPropertiesBuilder {
        
    private static void initAclProperties( AclProperties aclProperties ,Properties props){
        
        aclProperties.setOwnerPermission( props.getProperty("owner.permission") );
        aclProperties.setAnonymousAccess(props.getProperty("anonymous.access") );
        aclProperties.setAuthenticatedAccess(props.getProperty("authenticated.access"));
        aclProperties.setDefaultdocPermissions(props.getProperty("defaultdoc.permissions"));
        aclProperties.setPersistenceProvider(props.getProperty("persistence.provider"));
        aclProperties.setInitialAdmin(props.getProperty("initial.admin"));
        aclProperties.setFileAclfolder(props.getProperty("file.aclfolder"));
        aclProperties.setFileLocalgroups(props.getProperty("file.localgroups"));
        aclProperties.setFileLocalusers(props.getProperty("file.localusers"));
        aclProperties.setFilePermissions(props.getProperty("file.permissions"));
        aclProperties.setDbUrl(props.getProperty("db.url"));
        aclProperties.setDbDriver(props.getProperty("db.driver"));
        aclProperties.setDbUser(props.getProperty("db.user"));
        aclProperties.setDbPwd(props.getProperty("db.pwd"));
        
    }
    public static AclProperties AclPropertiesBuilder ( Properties props ){
        AclProperties aclProperties = new AclProperties();
        initAclProperties( aclProperties, props );
        return aclProperties;
    }
    
    public static AclProperties AclPropertiesBuilder ( String propFileName ) throws IOException{
        AclProperties aclProperties = new AclProperties();
        InputStream inputStream = null;
        try {
                Properties prop = new Properties();
                inputStream = AclPropertiesBuilder.class.getClassLoader().getResourceAsStream(propFileName);

                if (inputStream != null) {
                        prop.load(inputStream);
                        initAclProperties( aclProperties , prop );
                        
                } else {
                        throw new FileNotFoundException("property file '" + propFileName + "' not found in the classpath");
                }
        }
         catch (Exception e) {
            System.out.println("Exception: " + e);
        } finally {
                inputStream.close();
                return aclProperties;
        }
    }
  
}
