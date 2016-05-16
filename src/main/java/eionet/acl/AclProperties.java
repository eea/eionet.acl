package eionet.acl;

/**
 *
 * @author Aris Katsanas <aka@eworx.gr>
 */
public class AclProperties {
    
    private String ownerPermission;
    private String anonymousAccess;
    private String authenticatedAccess;
    private String defaultdocPermissions;
    private String persistenceProvider;
    private String initialAdmin;
    private String fileAclfolder;
    private String fileLocalgroups;
    private String fileLocalusers;
    private String filePermissions;
    private String dbUrl;
    private String dbDriver;
    private String dbUser;
    private String dbPwd;
    
    public String getOwnerPermission() {
        return ownerPermission;
    }

    public void setOwnerPermission(String ownerPermission) {
        this.ownerPermission = ownerPermission;
    }

    public String getAnonymousAccess() {
        return anonymousAccess;
    }

    public void setAnonymousAccess(String anonymousAccess) {
        this.anonymousAccess = anonymousAccess;
    }

    public String getAuthenticatedAccess() {
        return authenticatedAccess;
    }

    public void setAuthenticatedAccess(String authenticatedAccess) {
        this.authenticatedAccess = authenticatedAccess;
    }

    public String getDefaultdocPermissions() {
        return defaultdocPermissions;
    }

    public void setDefaultdocPermissions(String defaultdocPermissions) {
        this.defaultdocPermissions = defaultdocPermissions;
    }

    public String getPersistenceProvider() {
        return persistenceProvider;
    }

    public void setPersistenceProvider(String persistenceProvider) {
        this.persistenceProvider = persistenceProvider;
    }

    public String getInitialAdmin() {
        return initialAdmin;
    }

    public void setInitialAdmin(String initialAdmin) {
        this.initialAdmin = initialAdmin;
    }

    public String getFileAclfolder() {
        return fileAclfolder;
    }

    public void setFileAclfolder(String fileAclfolder) {
        this.fileAclfolder = fileAclfolder;
    }

    public String getFileLocalgroups() {
        return fileLocalgroups;
    }

    public void setFileLocalgroups(String fileLocalgroups) {
        this.fileLocalgroups = fileLocalgroups;
    }

    public String getFileLocalusers() {
        return fileLocalusers;
    }

    public void setFileLocalusers(String fileLocalusers) {
        this.fileLocalusers = fileLocalusers;
    }

    public String getFilePermissions() {
        return filePermissions;
    }

    public void setFilePermissions(String filePermissions) {
        this.filePermissions = filePermissions;
    }

    public String getDbUrl() {
        return dbUrl;
    }

    public void setDbUrl(String dbUrl) {
        this.dbUrl = dbUrl;
    }

    public String getDbDriver() {
        return dbDriver;
    }

    public void setDbDriver(String dbDriver) {
        this.dbDriver = dbDriver;
    }

    public String getDbUser() {
        return dbUser;
    }

    public void setDbUser(String dbUser) {
        this.dbUser = dbUser;
    }

    public String getDbPwd() {
        return dbPwd;
    }

    public void setDbPwd(String dbPwd) {
        this.dbPwd = dbPwd;
    }
    
    public AclProperties(){
        
    }
                                                    
}
