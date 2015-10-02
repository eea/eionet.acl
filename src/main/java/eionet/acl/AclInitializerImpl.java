package eionet.acl;

import eionet.propertyplaceholderresolver.CircularReferenceException;
import eionet.propertyplaceholderresolver.ConfigurationPropertyResolver;
import eionet.propertyplaceholderresolver.UnresolvedPropertyException;
import eionet.propertyplaceholderresolver.util.ConfigurationLoadException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author Ervis Zyka <ez@eworx.gr>
 */
public final class AclInitializerImpl implements AclInitializer {

    private static final Logger LOGGER = Logger.getLogger(AclInitializerImpl.class.getName());
    private final String classpathDirectoryName;

    private final String filesystemTargetDirectory;
    private final String gdemGroupFilePath;

    public AclInitializerImpl(String classpathDirectoryName, ConfigurationPropertyResolver configurationPropertyResolver) throws IOException, UnresolvedPropertyException, CircularReferenceException, ConfigurationLoadException {
        this.classpathDirectoryName = classpathDirectoryName;
        this.filesystemTargetDirectory = configurationPropertyResolver.resolveValue("file.aclfolder");
        this.gdemGroupFilePath = configurationPropertyResolver.resolveValue("file.localgroups");

    }
    
    public void execute() throws IOException {
        initializeAcl(filesystemTargetDirectory);
        initializeGdemGroup(gdemGroupFilePath);
    }

    @Override
    public void initializeAcl(String target) throws IOException {
        if (isAclInitiazed(target)) {
            return;
        }
        String classPathAclDirectoryFilepath = this.getClass().getClassLoader().getResource(classpathDirectoryName).getFile();
        copyAclDirectory(classPathAclDirectoryFilepath, this.filesystemTargetDirectory);
    }

    @Override
    public boolean isAclInitiazed(String AclDestUrl) {
        File file = new File(this.gdemGroupFilePath);
        boolean exists = file.exists();
        LOGGER.log(Level.INFO, "Acl initialized: {0}", exists);
        return exists;
    }

    void copyAclDirectory(String source, String target) throws IOException {
        File sourceDirectory = new File(source);
        File targetDirectory = new File(target);
        FileUtils.copyDirectory(sourceDirectory, targetDirectory);
        LOGGER.log(Level.INFO, "Successfully copied directory...{0}", target);
    }

    String getAdmins() {
        return System.getProperty("initial.admin");
    }

    void initializeGdemGroup(String path) {
        String admins = getAdmins();
        if (admins == null) {
            return;
        }
        File file = new File(path);
        if (file.exists()) {
            try {
                OutputStream ow = new FileOutputStream(file);
                try {
                    ow.write(String.format("gdem_admin:%s", admins).getBytes());
                    ow.flush();
                    ow.close();
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                    LOGGER.log(Level.SEVERE, null, ex);
                }
            } catch (FileNotFoundException ex) {
                LOGGER.log(Level.SEVERE, null, ex);
            }
        }
    }
}
