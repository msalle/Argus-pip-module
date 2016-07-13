// Copyright (c) FOM-Nikhef 2016-
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Authors:
// 2016-
// Mischa Salle <msalle@nikhef.nl>
// Rens Visser <rensv@nikhef.nl>
// NIKHEF Amsterdam, the Netherlands
// <grid-mw-security@nikhef.nl>

package org.glite.authz.pep.pip.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;

import java.util.Set;

import org.glite.authz.pep.pip.PIPProcessingException;


import java.util.ArrayList;
import java.nio.file.Path;
import java.nio.file.DirectoryStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.io.BufferedReader;
import java.net.URLDecoder;
import java.nio.file.attribute.FileTime;
import java.util.Calendar;
import java.nio.charset.Charset;

import java.io.IOException;
import java.text.ParseException;


/**
 * This PIP searches for all appearances of the issuer of the end-entity
 * certificate in the IGTF .info files. The resulting set is pushed into a
 * {@value #ATTR_CA_POLICY_NAMES} attribute.
 * @author Mischa Sall&eacute;, Rens Visser 
 */
public class PolicyNamesPIP extends AbstractPolicyInformationPoint {
    /** Class logger instance */
    private final Logger log = LoggerFactory.getLogger(PolicyNamesPIP.class);


    /** Default name of issuer DN attribute ({@value}) */
    protected final static String ATTR_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** Default name of CA policy names attribute ({@value}) */
    protected final static String ATTR_CA_POLICY_NAMES = "http://authz-interop.org/xacml/subject/ca-policy-names";

    /** Default trust dir ({@value}) */
    protected final static String TRUST_DIR = "/etc/grid-security/certificates";

    /** Extension of info file ({@value}) */
    protected final static String FILE_SFX = ".info";

    /** Key in info file starting subject DNs ({@value}) */
    protected final static String SUBJECT_KEY = "subjectdn";

    /** Default time interval (in msec) after which info files will be
     * reprocessed ({@value}) */
    protected final static long UPDATEINTERVAL = 6*3600*1000;


    ////////////////////////////////////////////////////////////////////////
    // instance variables, settable
    ////////////////////////////////////////////////////////////////////////
     
    /** Time interval (in msec) after which info files will be
     * reprocessed, default {@link #UPDATEINTERVAL}.
     * @see #setUpdateInterval(long) */
    private long update_interval = UPDATEINTERVAL;

    /** Info file directory, default {@link #TRUST_DIR}.
     * @see #setTrustDir(String)
     * @see #TRUST_DIR */
    private String trust_dir=TRUST_DIR;

    /** Name of attribute set by PIP, default {@link #ATTR_CA_POLICY_NAMES}
     * @see #setAttributeName(String) */
    private String attribute_name = ATTR_CA_POLICY_NAMES;

    ////////////////////////////////////////////////////////////////////////
    // Internal variables, internal use only
    ////////////////////////////////////////////////////////////////////////
    
    /** Last time when info files where being processed. */
    private long lastUpdated=0;

    /** Cached list of info file {@link Entry} */
    private ArrayList<Entry> cacheList=null;



    /** Internal type of info file entries */
    private static class Entry	{
	/** full path of this info file */
	Path path;
	/** name of this info entry (basename of info file) */
	String name;
	/** last modification time of this info file */
	FileTime modified;
	/** array of subject DNs for this info file */
	String[] subjectdns;

	/**
	 * Constructor, setting all variables
	 * @param path path of the info file
	 * @param name name of the policy
	 * @param modified last modification time of info file
	 * @param subjectdns array of subject DNs valid for this policy
	 */
	private Entry(Path path, String name, FileTime modified, String[] subjectdns)	{
	    this.path=path;
	    this.name=name;
	    this.modified=modified;
	    this.subjectdns=subjectdns;
	}

	/**
	 * Constructor, setting only name and modified from path.
	 * @param path path of the info file
	 * @param subjectdns array of subject DNs valid for this policy
	 */
	private Entry(Path path, String[] subjectdns) {
	    try {
		this.modified=Files.getLastModifiedTime(path);
	    } catch (IOException e) { // Cannot initialize: use 1/1/1970
		this.modified=FileTime.fromMillis(0);
	    }
	    String name=path.getFileName().toString();
	    this.name=name.substring(0, name.length()-FILE_SFX.length());
	    this.path=path;
	    this.subjectdns=subjectdns;
	}
	
    }

    
    ////////////////////////////////////////////////////////////////////////
    // Setter methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Sets the time interval (in msec) after which info files will be
     * reprocessed, default {@link #UPDATEINTERVAL}.
     * @param msecs number of millisecs between updates
     * @see #UPDATEINTERVAL
     */
    protected void setUpdateInterval(long msecs)    {
	update_interval=msecs;
    }
   
    /**
     * Sets the {@link #trust_dir} for this instance when different from the
     * current value. It also resets the {@link #cacheList} since that is no
     * longer valid.
     * @param trustDir directory where info files are located.
     * @see #TRUST_DIR
     */
    protected void setTrustDir(String trustDir)    {
	if (trustDir!=null && !trust_dir.equals(trustDir))    {
	    trust_dir=trustDir;
	    cacheList=null;
	}
    }

    /**
     * Sets the output attribute name, default {@link #ATTR_CA_POLICY_NAMES}.
     * @param attributeName name of attribute set by this PIP
     */
    protected void setAttributeName(String attributeName)    {
	attribute_name=attributeName;
    }
  

    /**
     * constructor for a {@link PolicyNamesPIP} instance, specifying both the
     * pipid and the {@link #trust_dir}. When trust_dir is {@code null}, keep
     * the current trust_dir {@link #trust_dir}.
     * @param pipid ID for this PIP
     * @param trustDir directory containing info files
     * @see #PolicyNamesPIP(String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid, String trustDir) throws IOException	{
	super(pipid);

	// Set internal trust_dir
	setTrustDir(trustDir);

	// Initial reading/parsing of info files
	updateList(trust_dir);
    }

    /**
     * constructor for a {@link PolicyNamesPIP} instance using default {@link
     * #trust_dir}.
     * @param pipid ID for this PIP
     * @see #PolicyNamesPIP(String,String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid)	throws IOException {
	this(pipid, null);
    }


    /**
     * {@inheritDoc}
     * This PIP adds a {@value #ATTR_CA_POLICY_NAMES} attribute to the
     * corresponding subjects. The value(s) of this attribute are the short
     * names of all the {@value #FILE_SFX} files that match the value of the
     * {@value ATTR_X509_ISSUER} attribute.
     * @param request the incoming request.
     * @throws PIPProcessingException in case of errors.
     * @return boolean: true when attribute has been populated, false otherwise.
     */
    public boolean populateRequest(Request request) throws PIPProcessingException {
	long t0=System.nanoTime();
	boolean pipprocessed=false;
	String issuerdn=null;

	// Get all subjects from the request, should be at least one, warn
	// when there are more than 1
	Set<Subject> subjects = request.getSubjects();
	if (subjects.isEmpty())	{
	    log.error("Request has no subjects");
	    throw new PIPProcessingException("No subject found in request");
	}
	if (subjects.size()>1)
	    log.warn("Request has "+subjects.size()+" subjects, taking first match");

	// Loop over all subjects
	for (Subject subject : subjects) {
	    // Loop over all attributes, looking for ATTR_X509_ISSUER
	    Set<Attribute> attributes = subject.getAttributes();
	    for (Attribute attr: attributes) {
		if (ATTR_X509_ISSUER.equals(attr.getId())) {
		    // Take first value (it should be singlevalued)
		    Object tmp = attr.getValues().iterator().next();
		    issuerdn = (tmp!=null ? tmp.toString() : null);
		    break;
		}
	    }

	    // Did we find the issuer attribute?
	    if (issuerdn==null)	{
		log.info("Subject has no or invalid "+ATTR_X509_ISSUER+
			 " attribute set");
		continue;
	    }

	    // Look for the issuerdn in the .info files
	    String[] policynames=new String[0];
	    try {
		policynames=findSubjectDN(issuerdn);
	    } catch (IOException e)	{
		log.error("I/O error reading info files: "+e.getMessage());
		throw new PIPProcessingException("I/O error reading info files: "+e.getMessage());
	    }

	    // Log total number of matching policies
	    log.debug("Found "+policynames.length+" matching policies");

	    // Check that we found any names
	    if (policynames.length==0)	{
		log.info("No matching info file for this subject");
		continue;
	    }

	    // Create new attribute and add the policy names
	    Attribute attr_policynames =
		new Attribute(attribute_name,
			      Attribute.DT_STRING);
	    Set<Object> values = attr_policynames.getValues();
	    for (int i=0; i<policynames.length; i++)
		values.add(policynames[i]);

	    // Add to the current subject
	    attributes.add(attr_policynames);
	    pipprocessed=true;
	    log.debug("Added attribute \""+attribute_name+"\"");
	}

	// Log statistics
	log.debug("PIP parsing took "+(System.nanoTime()-t0)/1000000.0+" msec");

	// No issuer DN found, attribute not set.
	return pipprocessed;

    }

    /**
     * Tries to find given subjectDN in the info files in {@link #trust_dir}.
     * @param dn String subject DN to look for
     * @return array of String with all the matching info files
     * @throws IOException upon reading errors in updateList
     */
    protected String[] findSubjectDN(String dn) throws IOException   {
	// Is the cached list valid?
	long now=Calendar.getInstance().getTimeInMillis();

	// Check whether cached list needs updating
	if (now-lastUpdated > update_interval)	{
	    lastUpdated=now; // prevent other threads from updating
	    updateList();
	}

	// Protect against empty cacheList
	if (cacheList == null)
	    return new String[0];

	// Copy the cacheList pointer, it might get updated.
	ArrayList<Entry> entryList = cacheList;

	// Initialize an empty list of policynames
	ArrayList<String> policynames = new ArrayList<String>();

	// Loop over the cached list and look for match
	for (int i=0; i<entryList.size(); i++)    {
	    Entry entry=entryList.get(i);
	    String[] dns=entry.subjectdns;
	    for (int j=0; j<dns.length; j++)	{
		if (dn.equals(dns[j]))  {
		    policynames.add(entry.name);
		    break; // subject dn loop
		}
	    }
	}
	return policynames.toArray(new String[0]);
    }

    /**
     * Update internal, cached list of parsed-out info files in the previously
     * set or default trust_dir.
     * @see #updateList(String)
     * @see #setTrustDir(String)
     * @throws IOException upon reading errors
     */
    protected void updateList() throws IOException    {
	updateList(trust_dir);
    }

    /**
     * Update internal, cached list of parsed-out info files in the specified
     * trust_dir.
     * @param trust_dir directory containing .info files
     * @see #updateList()
     * @throws IOException upon reading errors
     */
    protected void updateList(String trust_dir) throws IOException    {
	long t0=System.nanoTime();

	// Will be new list of Entries
	ArrayList<Entry> newList = new ArrayList<Entry>();

	// Get list of info files
	ArrayList<Path> infofiles;
	try {
	    infofiles=getInfoFiles(trust_dir);
	} catch (IOException e)	{
	    throw new IOException("getInfoFiles() failed: "+e.getMessage());
	}

	// Initialize counters
	int nentries_before=0, nupdated=0;

	// Get cached list of entries
	if (cacheList!=null)	{
	    ArrayList<Entry> oldList=cacheList;
	    nentries_before=oldList.size();
	    // Check old list and copy into new list after updating
	    for (int j=0; j<nentries_before; j++) {
		Entry entry=oldList.get(j);
		Path path = entry.path; // specific info file path
		for (int i=0; i<infofiles.size(); i++)   {
		    if (path.equals(infofiles.get(i)))	{ // File still present
			infofiles.remove(i); // don't check it again
			FileTime modified=Files.getLastModifiedTime(path);
			if (entry.modified.equals(modified)) {
			    // Add existing entry
			    newList.add(entry);
			} else {
			    // Get subjectdn array and create new updated entry
			    String[] subjectdns;
			    try {
				subjectdns=parseInfoFile(path);
			    } catch (ParseException e)	{
				log.error("Skipping: "+entry.name+
					  " has syntax errors: "+
					  e.getMessage());
				subjectdns=new String[0];
			    }
			    // Add to the new list
			    newList.add(new Entry(path, entry.name,
						  modified, subjectdns));
			    log.debug("Updated info file: "+entry.name);
			    nupdated++;
			}
			break; // Continue with next entry in oldlist
		    }
		}
	    }
	}
	// Store new size of infofiles and of newList
	int nfiles_after=infofiles.size(), nentries_after=newList.size();

	// Now handle new info files
	for (int i=0; i<nfiles_after; i++)	{
	    Path path=infofiles.get(i);
	    String[] subjectdns;
	    try {
		subjectdns=parseInfoFile(path);
	    } catch (ParseException e)	{
		log.error("Skipping due to syntax errors: "+e.getMessage());
		subjectdns=new String[0];
	    }

	    // Add to the new list
	    newList.add(new Entry(path, subjectdns));
	}

	// Replace cachelist with newlist
	cacheList=newList;

	// update last updated timestamp
	lastUpdated=Calendar.getInstance().getTimeInMillis();
   
	// Log statistics
	log.debug("Updated list ("+trust_dir+"): "+(System.nanoTime()-t0)/1000000.0+" msec ("+
	    (nentries_after-nupdated)+" copied, "+
	    nupdated+" updated, "+
	    (nentries_before-nentries_after)+" removed, "+
	    nfiles_after+" new)");
    }

    /**
     * Find all {@value #FILE_SFX} files (not symlinks) in given trust dir.
     * @param trust_dir directory containing {@value #FILE_SFX} files
     * @return ArrayList of Path
     * @throws IOException upon directory reading errors
     */
    private static ArrayList<Path> getInfoFiles(String trust_dir)
	throws IOException
    {
	// Filter for filtering out .info file that aren't symlinks.
	DirectoryStream.Filter<Path> filter=new DirectoryStream.Filter<Path>() {
	    public boolean accept(Path path)   {
		return (path.toString().endsWith(FILE_SFX) &&
		        Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
	    }
	};

	// Protect against null trust_dir
	if (trust_dir==null)
	    throw new IOException("Trust dir is null");

	// Get all files as a stream
	DirectoryStream<Path> stream=null;
	try {
	    stream = Files.newDirectoryStream(Paths.get(trust_dir), filter);
	} catch(IOException e)	{
	    throw new IOException("Trust dir has problems: "+e.getMessage());
	}

	// Initialize file array
	ArrayList<Path> files = new ArrayList<Path>();
	// Add all entries
	for (Path entry: stream)
	    files.add(entry);

	return files;
    }


    /**
     * Parse an {@value #FILE_SFX} file and obtain a String array of subjectDN
     * entries.
     * @param path path of the info file
     * @return array of subject DN strings
     * @throws IOException in case of I/O errors
     * @throws ParseException in case of subjectdn parsing errors
     */
    private static String[] parseInfoFile(Path path)
	throws ParseException, IOException
    {
	String name=path.toString();
	BufferedReader reader=null;
	StringBuilder linebuilder=new StringBuilder();
	String newline;
	String value=null;

	try {
	    reader=Files.newBufferedReader(path, Charset.defaultCharset());
	} catch (IOException e)	{
	    throw new IOException("Cannot open "+name+": "+e.getMessage());
	}
	
	// initialize line
	try {
	    while ( (newline=reader.readLine()) != null )   {
		// Append to existing or empty line
		linebuilder.append(newline);

		// Handle continuation char
		int end=linebuilder.length()-1;
		if (end>=0 && linebuilder.charAt(end)=='\\')	{
		    linebuilder.deleteCharAt(end);
		    continue;
		}

		// Remove leading whitespace (easiest when converting to String)
		String line=linebuilder.toString().trim();
		// Only look at non-empty non-comment lines
		if (!line.isEmpty() && line.charAt(0)!='#')	{
		    // Split into key / value and look for subjectdn
		    int sep=line.indexOf('=');
		    if (sep>=0 && SUBJECT_KEY.equals(line.substring(0,sep).trim())) {
			value=line.substring(sep+1).trim();
			break;
		    }
		}

		// Continue with next line
		linebuilder.setLength(0);
	    }
	} catch (IOException e)	{
	    // Try to close, this might throw a new IOException. We're throwing
	    // one in any case.
	    reader.close();
	    throw new IOException("Reading from "+name+" failed: "+e.getMessage());
	}

	// Close reader
	try {
	    reader.close();
	} catch (IOException e)	{
	    throw new IOException("Closing "+name+" failed: "+e.getMessage());
	}

	// Did we find the KEY?
	if (value==null || value.isEmpty())
	    throw new ParseException(name+": No "+SUBJECT_KEY+" key found", 0);

	// Now parse the value part
	ArrayList<String> list=new ArrayList<String>();
	int pos=0;
	while (true)	{
	    // Check value start with quote
	    if (value.charAt(pos)!='"')
		throw new ParseException(name+": "+SUBJECT_KEY+" value invalid: "+value, pos);
	    // Look for end quote (pos==quote_1)
	    int quote=value.indexOf('"', pos+1);
	    if ( quote < 0 )
		throw new ParseException(name+": Missing end-quote", pos+1);
	    // Add url-decoded value to the list
	    list.add(URLDecoder.decode(value.substring(pos+1,quote),"UTF-8"));
	    // Skip all trailing white-space and commas
	    boolean foundComma=false;
	    for (pos=quote+1; pos<value.length(); pos++)    {
		// Keep track of whether we found a comma: need at least one
		if (value.charAt(pos)==',') {
		    foundComma=true; continue;
		}
		if (value.charAt(pos)!=' ' && value.charAt(pos)!='\t')
		    break;
	    }
	    // Did we hit the end-of-line or find a comment char?
	    if (pos==value.length() || value.charAt(pos)=='#') // we're done
		break;
	    // Check we found at least one comma
	    if (!foundComma)
		throw new ParseException(name+": Missing comma delimiter before new entry", pos);
	}

	// Convert to array and return
	return list.toArray(new String[0]);
    }
}
