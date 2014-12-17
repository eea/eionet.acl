package eionet.acl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eionet.acl.impl.GroupImpl;
import eionet.acl.impl.PermissionImpl;
import eionet.acl.impl.PrincipalImpl;


/**
 * Read and write XML-based ACL files.
 * @author heinljab
 */
public class XmlFileReaderWriter {

    /**
     * Read a group file.
     *
     * @param fileFullPath
     */
    public static void readGroups(String fileFullPath, HashMap groups, HashMap users) throws SignOnException {

        try {
            File file = new File(fileFullPath);
            if (!file.exists() || !file.isFile())
                throw new SignOnException("File does not exist: " + fileFullPath);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(fileFullPath);

            // get the root elememt
            Element rootElm = dom.getDocumentElement();

            // get nodelist of <group> elements
            NodeList nl = rootElm.getElementsByTagName("group");
            for (int i = 0; nl != null && i < nl.getLength(); i++) {
                Element elm = (Element) nl.item(i);
                Group group = readGroup(elm, users);
                groups.put(group.getName(), group);
            }
        } catch (FactoryConfigurationError e) {
            e.printStackTrace(System.out);
            // unable to get a document builder factory
            throw new SignOnException(e, "Failed to read groups from " + fileFullPath
                    + ", unable to get a document builder factory");
        } catch (ParserConfigurationException e) {
            e.printStackTrace(System.out);
            // parser was unable to be configured
            throw new SignOnException(e, "Failed to read groups from " + fileFullPath + ", parser configuration problem");
        } catch (SAXException e) {
            e.printStackTrace(System.out);
            // parsing error
            throw new SignOnException(e, "Failed to read groups from " + fileFullPath + ", parsing error");
        } catch (IOException e) {
            e.printStackTrace(System.out);
            // i/o error
            throw new SignOnException(e, "Failed to read groups from " + fileFullPath + ", I/O error");
        }
    }

    /**
     * Read one group in XML DOM.
     * @param groupElm
     * @return Group object or null
     */
    private static Group readGroup(Element groupElm, HashMap allUsers) {

        String groupID = groupElm.getAttribute("id");
        if (groupID == null || groupID.length() == 0)
            return null;

        Group group = new GroupImpl(groupID);
        NodeList nl = groupElm.getElementsByTagName("member");
        for (int i = 0; nl != null && i < nl.getLength(); i++) {
            Element elm = (Element) nl.item(i);
            String userID = elm.getAttribute("userid");
            if (userID != null && userID.length() > 0) {
                Principal principal = new PrincipalImpl(userID);
                allUsers.put(userID, principal);
                group.addMember(principal);
            }
        }

        return group;
    }

    /**
     * Write groups to XML file.
     *
     * @param fileFullPath
     * @param groups
     * @throws SignOnException
     */
    public static void writeGroups(String fileFullPath, Map groups) throws SignOnException {

        TransformerFactory trf = TransformerFactory.newInstance();

        FileOutputStream fos = null;
        OutputStreamWriter osw = null;
        try {
            Transformer tr = trf.newTransformer();
            tr.setOutputProperty(OutputKeys.METHOD, "xml");
            tr.setOutputProperty(OutputKeys.INDENT, "yes");

            Document dom = groupsToDOM(groups);

            fos = new FileOutputStream(new File(fileFullPath));
            osw = new OutputStreamWriter(fos, "UTF-8");
            tr.transform(new DOMSource(dom), new StreamResult(osw));
        } catch (TransformerConfigurationException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write groups to " + fileFullPath + ", TransformerConfigurationException");
        } catch (ParserConfigurationException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write groups to " + fileFullPath + ", ParserConfigurationException");
        } catch (FileNotFoundException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write groups to " + fileFullPath
                    + ", problem with creating or opening the file");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write groups to " + fileFullPath + ", UnsupportedEncodingException");
        } catch (TransformerException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write groups to " + fileFullPath + ", TransformerException");
        } finally {
            try {
                if (osw != null)
                    osw.close();
                if (fos != null)
                    fos.close();
            } catch (Exception e) {
            }
        }
    }

    /**
     *
     * @return XML DOM Document.
     * @throws ParserConfigurationException
     */
    private static Document groupsToDOM(Map groups) throws ParserConfigurationException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element rootElm = document.createElement("localgroups");
        document.appendChild(rootElm);

        if (groups == null || groups.size() == 0)
            return document;

        for (Iterator i = groups.keySet().iterator(); i.hasNext();) {
            String groupID = (String) i.next();
            if (groupID != null) {
                Element groupElm = document.createElement("group");
                groupElm.setAttribute("id", groupID);
                rootElm.appendChild(groupElm);

                Vector members = (Vector) groups.get(groupID);
                for (int j = 0; members != null && j < members.size(); j++) {
                    String userID = (String) members.get(j);
                    if (userID != null) {
                        Element memberElm = document.createElement("member");
                        memberElm.setAttribute("userid", userID);
                        groupElm.appendChild(memberElm);
                    }
                }
            }
        }

        return document;
    }

    /**
     * Checks an XML file for wellformedness by parsing it.
     *
     * @return true if the file is wellformed.
     * @throws IOException
     * @throws ParserConfigurationException
     */
    public static boolean isValidXmlFile(String fileFullPath) throws IOException, ParserConfigurationException {

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            db.parse(fileFullPath);
        } catch (SAXException e) {
            return false;
        }

        return true;
    }

    /**
     * Read permission descriptions from XML file.
     *
     * @param fileFullPath
     * @param permissions
     * @param prmDescrs
     * @throws SignOnException
     */
    public static void readPermissions(String fileFullPath, Map permissions, Map prmDescrs) throws SignOnException {

        try {
            File file = new File(fileFullPath);
            if (!file.exists() || !file.isFile())
                throw new SignOnException("File does not exist: " + fileFullPath);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(fileFullPath);

            // get the root elememt
            Element rootElm = dom.getDocumentElement();

            // get nodelist of <group> elements
            NodeList nl = rootElm.getElementsByTagName("permission");
            for (int i = 0; nl != null && i < nl.getLength(); i++) {
                Element elm = (Element) nl.item(i);
                String prmID = elm.getAttribute("id");
                String prmDescr = elm.getAttribute("description");
                if (prmID != null) {
                    permissions.put(prmID, new PermissionImpl(prmID));
                    prmDescrs.put(prmID, prmDescr);
                }
            }
        } catch (FactoryConfigurationError e) {
            e.printStackTrace(System.out);
            // unable to get a document builder factory
            throw new SignOnException(e, "Failed to read permissions from " + fileFullPath
                    + ", unable to get a document builder factory");
        } catch (ParserConfigurationException e) {
            e.printStackTrace(System.out);
            // parser was unable to be configured
            throw new SignOnException(e, "Failed to read permissions from " + fileFullPath
                    + ", parser configuration problem");
        } catch (SAXException e) {
            e.printStackTrace(System.out);
            // parsing error
            throw new SignOnException(e, "Failed to read permissions from " + fileFullPath + ", parsing error");
        } catch (IOException e) {
            e.printStackTrace(System.out);
            // i/o error
            throw new SignOnException(e, "Failed to read permissions from " + fileFullPath + ", I/O error");
        }
    }

    /**
     * Read ACL from XML file.
     *
     * @param fileFullPath
     * @param acl
     * @throws SignOnException
     */
    public static void readACL(String fileFullPath, AccessControlList acl) throws SignOnException {

        try {
            File file = new File(fileFullPath);
            if (!file.exists() || !file.isFile())
                throw new SignOnException("File does not exist: " + fileFullPath);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document dom = db.parse(fileFullPath);

            // get the root elememt (<acl>)
            Element rootElm = dom.getDocumentElement();
            String aclDescription = rootElm.getAttribute("description");
            if (aclDescription != null)
                acl.setDescription(aclDescription);

            // get entry nodelist
            NodeList nl = rootElm.getElementsByTagName("entries");
            if (nl == null || nl.getLength() == 0)
                throw new SignOnException("Missing <entries> element");
            NodeList nlEntry = ((Element) nl.item(0)).getElementsByTagName("entry");
            if (nlEntry == null || nlEntry.getLength() == 0)
                throw new SignOnException("Missing <entry> element");

            // loop through entries, for each of them construct an acl row in the old format (i.e. user:roug:i,v,u),
            // collect those rows into a list
            ArrayList rows = new ArrayList();
            for (int i = 0; i < nlEntry.getLength(); i++) {

                // get entry's type
                Element entryElm = (Element) nlEntry.item(i);
                String entryType = entryElm.getAttribute("type");
                boolean isNotObject = entryType != null;

                // get principal, its type and its id
                nl = entryElm.getElementsByTagName("principal");
                if (nl == null || nl.getLength() == 0)
                    throw new SignOnException("Missing <principal> element");
                Element principalElm = (Element) nl.item(0);
                String principalType = principalElm.getAttribute("type");
                String principalId = principalElm.getAttribute("id");
                if (principalType == null || principalId == null)
                    throw new SignOnException("Missing 'type' or 'id' attribute in " + principalElm.getTagName() + "element");
                if (!AccessControlList.isLegalPrincipalType(principalType))
                    throw new SignOnException("Unknown principal type: " + principalType);

                // get permissions nodelist
                nl = entryElm.getElementsByTagName("permissions");
                if (nl == null || nl.getLength() == 0)
                    throw new SignOnException("Missing <permissions> element");
                NodeList nlPermissions = ((Element) nl.item(0)).getElementsByTagName("permission");

                // loop over permissions in this entry,
                // construct an acl row in the old plain text way (i.e. user:roug:i,v,u)
                int j;
                StringBuffer rowStrBuf = new StringBuffer();
                rowStrBuf.append(principalType).append(":").append(principalId).append(":");
                for (j = 0; nlPermissions != null && j < nlPermissions.getLength(); j++) {

                    Element prmElm = (Element) nlPermissions.item(j);
                    String prmId = prmElm.getAttribute("id");
                    if (prmId == null)
                        throw new SignOnException("Missing 'id' attribute in " + prmElm.getTagName() + "element");
                    else {
                        if (j > 0)
                            rowStrBuf.append(",");
                        rowStrBuf.append(prmId);
                    }
                }

                // if this is a DOC- or DCC- type entry, append ":doc" or ":ddc" to the end of the constructed row string
                if (isNotObject && j > 0) {
                    rowStrBuf.append(":").append(entryType);
                }
                // add row to the list
                rows.add(rowStrBuf.toString());
            }

            // finally, process the rows constructed and collected above
            acl.processAclRows(rows);
        } catch (FactoryConfigurationError e) {
            e.printStackTrace(System.out);
            // unable to get a document builder factory
            throw new SignOnException(e, "Failed to read acl from " + fileFullPath + ", unable to get a document builder factory");
        } catch (ParserConfigurationException e) {
            e.printStackTrace(System.out);
            // parser was unable to be configured
            throw new SignOnException(e, "Failed to read acl from " + fileFullPath + ", parser configuration problem");
        } catch (SAXException e) {
            e.printStackTrace(System.out);
            // parsing error
            throw new SignOnException(e, "Failed to read acl from " + fileFullPath + ", parsing error");
        } catch (IOException e) {
            e.printStackTrace(System.out);
            // i/o error
            throw new SignOnException(e, "Failed to read acl from " + fileFullPath + ", I/O error");
        }
    }

    /**
     * Write ACL to XML file.
     *
     * @param aclEntries
     * @throws SignOnException
     */
    public static void writeACL(String fileFullPath, Map<String, String> aclAttrs, List aclEntries) throws SignOnException {

        TransformerFactory trf = TransformerFactory.newInstance();

        FileOutputStream fos = null;
        OutputStreamWriter osw = null;
        try {
            Transformer tr = trf.newTransformer();
            tr.setOutputProperty(OutputKeys.METHOD, "xml");
            tr.setOutputProperty(OutputKeys.INDENT, "yes");

            // TODO: init dom
            Document dom = aclToDOM(aclAttrs, aclEntries);

            fos = new FileOutputStream(new File(fileFullPath));
            osw = new OutputStreamWriter(fos, "UTF-8");
            tr.transform(new DOMSource(dom), new StreamResult(osw));
        } catch (TransformerConfigurationException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write acl to " + fileFullPath + ", TransformerConfigurationException");
        } catch (ParserConfigurationException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write acl to " + fileFullPath + ", ParserConfigurationException");
        } catch (FileNotFoundException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write acl to " + fileFullPath + ", failure creating or opening the file");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write acl to " + fileFullPath + ", UnsupportedEncodingException");
        } catch (TransformerException e) {
            e.printStackTrace(System.out);
            throw new SignOnException(e, "Failed to write acl to " + fileFullPath + ", TransformerException");
        } finally {
            try {
                if (osw != null)
                    osw.close();
                if (fos != null)
                    fos.close();
            } catch (Exception e) {
            }
        }
    }

    /**
     *
     * @param entries
     * @return XML DOM Document
     */
    private static Document aclToDOM(Map<String, String> aclAttrs, List entries) throws ParserConfigurationException {

        // create document builder factory and document
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        // create acl root element, add it to document
        Element rootElm = document.createElement("acl");
        document.appendChild(rootElm);

        // set acl attributes
        if (aclAttrs != null && aclAttrs.size() > 0) {
            for (Iterator i = aclAttrs.keySet().iterator(); i.hasNext();) {
                String attrName = (String) i.next();
                rootElm.setAttribute(attrName, (String) aclAttrs.get(attrName));
            }
        }

        if (entries == null || entries.size() == 0)
            return document;

        // add acl entries
        Element entriesElm = document.createElement("entries");
        rootElm.appendChild(entriesElm);
        for (int i = 0; i < entries.size(); i++) {

            Hashtable entryHash = (Hashtable) entries.get(i);

            String principalType = (String) entryHash.get("type");
            String principalId = (String) entryHash.get("id");
            String permissions = (String) entryHash.get("perms");
            String entryType = (String) entryHash.get("acltype");
            if (entryType == null)
                entryType = "object";

            Element entryElm = document.createElement("entry");
            entryElm.setAttribute("type", entryType);
            entriesElm.appendChild(entryElm);

            Element principalElm = document.createElement("principal");
            principalElm.setAttribute("type", principalType);
            principalElm.setAttribute("id", principalId);
            entryElm.appendChild(principalElm);

            Element permissionsElm = document.createElement("permissions");
            entryElm.appendChild(permissionsElm);

            StringTokenizer permissionTokens = new StringTokenizer(permissions, ",");
            while (permissionTokens.hasMoreTokens()) {
                String prm = permissionTokens.nextToken().trim();
                Element permissionElm = document.createElement("permission");
                permissionElm.setAttribute("id", prm);
                permissionsElm.appendChild(permissionElm);
            }
        }

        return document;
    }

    /**
     * Test if the file contains XML by checking of the file starts with "&lt;?xml
     * and ends with "?&gt;". There is no requirement that the prologue exists in
     * an XML file or that there is a newline after the prologue, so this test is
     * not generic.
     *
     * @param fileFullPath
     * @return true if the file looks like XML
     * @throws IOException
     */
    public static boolean isXmlFileWannabe(String fileFullPath) throws IOException {

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(fileFullPath));
            String line = reader.readLine();
            return line != null && line.startsWith("<?xml") && line.trim().endsWith("?>");
        } finally {
            try {
                if (reader != null)
                    reader.close();
            } catch (Exception e) {
            }
        }
    }
}
