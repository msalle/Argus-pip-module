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

package org.glite.authz.pep.pip.provider.policynamespip;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.nio.file.Path;
import java.nio.file.DirectoryStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.FileTime;
import java.nio.charset.Charset;
import java.io.BufferedReader;
import java.net.URLDecoder;
import java.util.Calendar;

import java.io.IOException;
import java.text.ParseException;


/**
 * Subclass for {@link org.glite.authz.pep.pip.provider.PolicyNamesPIP}
 * providing a parsed cache of the subjectdn entries in the info files in the
 * trust directory.
 * @author Mischa Sall&eacute;
 */
public class Cache {
    /** Class logger instance */
    private final Logger log = LoggerFactory.getLogger(Cache.class);


    ////////////////////////////////////////////////////////////////////////
    // constants
    ////////////////////////////////////////////////////////////////////////
 
    /** Extension of info file ({@value}) */
    public final static String FILE_SFX = ".info";
    
    /** Key in info file starting subject DNs ({@value}) */
    public final static String SUBJECT_KEY = "subjectdn";

    /** Maximum level of info file recursion ({@value}) */
    public final static int MAX_RECURSION = 7;


    ////////////////////////////////////////////////////////////////////////
    // instance variables
    ////////////////////////////////////////////////////////////////////////

    /** Cached list of {@value #FILE_SFX} file entries in the trust_dir */
    private ArrayList<Entry> infoEntries = new ArrayList<Entry>();
    
    /** Cached list of {@value #FILE_SFX} file entries outside of the trust_dir */
    private ArrayList<Entry> extInfoEntries = new ArrayList<Entry>();
    
    /**
     * Directory containing the {@value #FILE_SFX} files
     * @see #getTrustDir
     */
    private String trust_dir = null;

    /**
     * Time when Cache was initialized
     * @see #getLifeTime
     */
    private long initTime = 0;

    /** Number of parsed entries in update */
    private int newentries;

    
    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////

    /**
     * constructs new Cache based on given trustDir
     * @param trustDir directory containing info files
     * @throws IOException on read errors for trust_dir or one of the info files
     * @see #Cache(Cache)
     */
    public Cache(String trustDir) throws IOException   {
	this.trust_dir = trustDir;
	this.update();
    }

    /**
     * constructs new Cache based on old Cache
     * @param oldCache previous Cache
     * @throws IOException on read errors for trust_dir or one of the info files
     * @see #Cache(String)
     */
    public Cache(Cache oldCache) throws IOException    {
	this.update(oldCache);
    }


    ////////////////////////////////////////////////////////////////////////
    // getter methods
    ////////////////////////////////////////////////////////////////////////
 
    /**
     * Returns the internal trust_dir
     * @return {@link #trust_dir} for this Cache
     */
    public String getTrustDir()  {
	return trust_dir;
    }

    /**
     * Returns the lifetime of this Cache
     * @return msecs since initialization of this Cache
     */
    public long getLifeTime()  {
	return Calendar.getInstance().getTimeInMillis()-initTime;
    }


    ////////////////////////////////////////////////////////////////////////
    // Main instance method
    ////////////////////////////////////////////////////////////////////////

    /**
     * Tries to find given issuer DN in the info files in {@link #trust_dir}.
     * @param issuerDN String issuer DN to look for
     * @return array of String with all the matching info files
     */
    public String[] matchIssuerDN(String issuerDN)    {
	// Protect against empty cache
	if (infoEntries == null)
	    return new String[0];

	// Initialize an empty list of policynames
	ArrayList<String> policynames = new ArrayList<String>();

	// Loop over the cached list and look for match
	for (int i=0; i<infoEntries.size(); i++)    {
	    Entry entry=infoEntries.get(i);
	    String[] subDNs=entry.subDNs;
	    for (int j=0; j<subDNs.length; j++)	{
		if (issuerDN.equals(subDNs[j]))  {
		    policynames.add(entry.name);
		    break; // subject dn loop
		}
	    }
	}
	// Convert ArrayList to an array and return
	return policynames.toArray(new String[0]);
    }


    ////////////////////////////////////////////////////////////////////////
    // Protected methods
    ////////////////////////////////////////////////////////////////////////

    /**
     * Updates the current cache not using existing one
     * @throws IOException on I/O errors
     * @see #update(Cache)
     */
    protected void update() throws IOException    {
	this.update(null);
    }

    /**
     * Update internal, cached list of parsed-out info files in the specified
     * trustDir.
     * @param oldCache previous Cache to be updated
     * @see #update()
     * @throws IOException upon reading errors
     */
    protected void update(Cache oldCache) throws IOException    {
	long t0=System.nanoTime();
	int nremoved=0, ncopiedupdated=0, nnew=0, nupdated=0, ncopied=0,
	    neremoved=0, necopiedupdated=0, nenew=0, neupdated=0, necopied=0;

	// Set initialization time
	initTime = Calendar.getInstance().getTimeInMillis();

	// Reset indicator for any change
	newentries=0;

	// Force directories to be the same
	if (oldCache!=null)
	    trust_dir=oldCache.getTrustDir();

	// Get current list of info files
	ArrayList<Path> infofiles, extinfofiles=new ArrayList<Path>();
	try {
	    infofiles=getInfoFiles(trust_dir);
	} catch (IOException e)	{
	    throw new IOException("getInfoFiles() failed: "+e.getMessage());
	}

	// Get cached list of entries
	if (oldCache!=null && oldCache.infoEntries!=null)   {
	    // Make a shallow copy of the two old lists: we want to change those
	    // lists, but not the entries themselves. Don't use clone() which is
	    // tricky to cast correctly (impossible without warnings).
	    ArrayList<Entry> oldInfoEntries = new ArrayList<Entry>(oldCache.infoEntries);

	    // Loop over new list of infofiles
	    for (int i=0; i<infofiles.size(); i++)  {
		// Get entry from the old entries or (re)parse it
		try {
		    Entry entry=getOrParseInfoFile(infofiles.get(i), oldInfoEntries);

		    // Add to new list
		    infoEntries.add(entry);

		    // Add all the external dependencies to the list
		    addExtDeps(entry, extinfofiles);
		} catch (ParseException e)  {
		    log.error("Syntax error, skipping "+infofiles.get(i));
		}
	    }
	    // Store counters
	    nremoved = oldInfoEntries.size();
	    ncopiedupdated = oldCache.infoEntries.size()-nremoved;
	    nnew = infoEntries.size() - ncopiedupdated;
	    nupdated = newentries - nnew;
	    ncopied = ncopiedupdated - nupdated;
	} else {
	    // Loop over new list of infofiles
	    for (int i=0; i<infofiles.size(); i++)  {
		// Get entry from the old entries or (re)parse it
		try {
		    Entry entry=parseInfoFile(infofiles.get(i));

		    // Add to new list
		    infoEntries.add(entry);

		    // Add all the external dependencies to the list
		    addExtDeps(entry, extinfofiles);
		} catch (ParseException e)  {
		    log.error("Syntax error, skipping "+infofiles.get(i));
		} 
	    }
	    // Store counters: anything parsed is new
	    nnew = infoEntries.size();
	}

	// Now handle the extinfofiles
	ArrayList<Entry> oldExtInfoEntries=null;
	if (oldCache!=null && oldCache.extInfoEntries!=null)
	    oldExtInfoEntries = new ArrayList<Entry>(oldCache.extInfoEntries);
	// Save number of copied & updated 'normal' info files
	int nonext_newentries=newentries;
	// Now loop over the list of externals
	for (int i=0; i<extinfofiles.size(); i++)   {
	    try {
		recurseParseExtInfoFile(extinfofiles.get(i),oldExtInfoEntries,0);
	    } catch (ParseException e)	{
		log.error("Parsing "+extinfofiles.get(i).getFileName()+
			  " failed: "+e.getMessage());
	    }
	}
	
	// Store externals counters
	if (oldExtInfoEntries==null)    {
	    nenew = extInfoEntries.size();
	} else {
	    neremoved = oldExtInfoEntries.size();
	    necopiedupdated = oldCache.extInfoEntries.size()-neremoved;
	    nenew = extInfoEntries.size() - necopiedupdated;
	    neupdated = (newentries-nonext_newentries)-nenew;
	    necopied = necopiedupdated - neupdated;
	}

	// Create the cumulative subject DN lists
	for (int i=0; i<infoEntries.size(); i++)
	    infoEntries.get(i).updateSubDNs();
	for (int i=0; i<extInfoEntries.size(); i++)
	    extInfoEntries.get(i).updateSubDNs();

	// Reprocess overall subDNs list when something changed
	if (newentries > 0) {
	    for (int i=0; i<infoEntries.size(); i++)
		infoEntries.get(i).updateSubDNs();
	    for (int i=0; i<extInfoEntries.size(); i++)
		extInfoEntries.get(i).updateSubDNs();
	}

	// Log statistics
	log.debug("Updated list ("+trust_dir+"): "+
	    (System.nanoTime()-t0)/1000000.0+" msec ("+
	    ncopied+" copied, "+nupdated+" updated, "+
	    nremoved+" removed, "+nnew+" new, externals: "+
	    necopied+" copied, "+neupdated+" updated, "+
	    neremoved+" removed, "+nenew+" new)");
    }


    ////////////////////////////////////////////////////////////////////////
    // Private helper methods
    ////////////////////////////////////////////////////////////////////////

    /**
     * Find all {@value #FILE_SFX} files (not symlinks) in given trust dir.
     * @param trust_dir directory containing {@value #FILE_SFX} files
     * @return ArrayList of Path
     * @throws IOException upon directory reading errors
     */
    private ArrayList<Path> getInfoFiles(String trust_dir) throws IOException {
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
     * Recursively parses the external infofile given by path, using a existing
     * list of external info file oldExtInfoEntries.
     * @param path infofile to handle
     * @param oldExtInfoEntries list of old (and possibly changed) external info
     * files
     * @param recursion current level of recursion
     * @throws IOException when reading file failed
     * @throws ParseException when the level of recursions is too large
     */
    private void recurseParseExtInfoFile(Path path,
					 ArrayList<Entry> oldExtInfoEntries,
					 int recursion)
	throws ParseException, IOException
    {
	if (recursion > MAX_RECURSION)
	    throw new ParseException(path.getFileName()+
		": Too many levels of recursion (max. "+MAX_RECURSION+")", 0);
	// First check the new entries
	if (getEntry(path, extInfoEntries)!=null) // already there
	    return;

	// Get it from the old entries or (re)parse it
	Entry entry;
	try {
	    if (oldExtInfoEntries != null)
		entry=getOrParseInfoFile(path, oldExtInfoEntries);
	    else
		entry=parseInfoFile(path);
	} catch (ParseException e)  {
	    throw new ParseException("Syntax error in external dependency "+
		path.getFileName(), e.getErrorOffset());
	}

	// Add it to the new list (it's not there yet)
	// entry is not yet in new list (we checked above), add it now
	extInfoEntries.add(entry);

	// Now handle the dependencies
	for (int i=0; i<entry.extdeps.size(); i++)
	    recurseParseExtInfoFile(entry.extdeps.get(i), oldExtInfoEntries, recursion+1);
    }

    /**
     * Looks for entry matching path in list of old entries or return a new one.
     * If found in the old list remove it from there, if it's also not modified,
     * use it, otherwise parse it.
     * @param path infofile
     * @param oldEntries list of existing entries.
     * @return old or new entry
     * @throws IOException in case of I/O errors
     * @throws ParseException in case of subjectdn parsing errors
     */
    private Entry getOrParseInfoFile(Path path, ArrayList<Entry> oldEntries)
	throws ParseException, IOException
    {
	Entry entry;
	boolean found=false;

	// Loop over old entries to see if it's there
	for (int i=0; i<oldEntries.size(); i++)    {
	    entry=oldEntries.get(i);
	    if (path.equals(entry.path))	{
		// Remove from old list: no need to recheck since we
		// either update or copy entry corresponding to this
		// path
		oldEntries.remove(i);
		// Found match, now check the filestamp
		if (entry.modified.equals(Files.getLastModifiedTime(path)))
		    return entry;
	    }
	}
	// No (unchanged) match: create new entry
	return parseInfoFile(path);
    }

    /**
     * Parse an {@value #FILE_SFX} file and obtain an internal {@link Entry}
     * containing all the Issuer DN and dependency information.
     * @param path path of the info file
     * @return {@link Entry} describing this file
     * @throws IOException in case of I/O errors
     * @throws ParseException in case of subjectdn parsing errors
     */
    private Entry parseInfoFile(Path path) throws ParseException, IOException {
	// First get the value of the subjectdn key, this can throw IOException
	String value = getSubjectDNvalue(path);

	// Did we find the KEY?
	if (value==null || value.isEmpty())
	    throw new ParseException(path.getFileName()+": No or empty "+SUBJECT_KEY+" key found", 0);

	// Create new Entry for this path, already setting the name and the like
	Entry entry=new Entry(path);

	// Parse out the value of the key into the entry, this can throw
	// IOException or ParseException
	parseSubjectDNvalue(entry, value);

	// Update global new/changed flag
	newentries++;

	// Now return the entry
	return entry;
    }

    /**
     * Parses an {@value #FILE_SFX} file for the {@link #SUBJECT_KEY} key and
     * returns the value.
     * @param path Path of this info file
     * @return String with the value of the {@link #SUBJECT_KEY}
     * @throws IOException when reading the file failed
     */
    private String getSubjectDNvalue(Path path) throws IOException	{
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

	// All done
	return value;
    }

    /**
     * Parses out the different components of a subjectdn value and puts the
     * results into the given entry. When a file: entry is found, it will
     * add the correct path to the right list of dependencies.
     * @param entry {@link Entry} to fill
     * @param value value of the subjectdn key
     * @throws ParseException on syntax errors in the value
     * @throws IOException on read errors with one of the info files
     */
    private void parseSubjectDNvalue(Entry entry, String value)
	throws ParseException, IOException
    {
	// Now parse the value part
	int pos=0, pos2;
	while (true)	{
	    // Check what we have here
	    if (value.charAt(pos)=='"')	{
		// Found CA subject DN: look for end quote (pos==quote_1)
		pos2=value.indexOf('"', pos+1);
		if ( pos2 < 0 )
		    throw new ParseException(entry.name+": Missing end-quote", pos+1);
		// Add url-decoded value to the subDN list
		entry.localSubDNs.add(URLDecoder.decode(value.substring(pos+1,pos2),"UTF-8"));
		// skip over end-quote
		pos2++;
	    } else if (value.substring(pos).startsWith("file:"))    {
		// Found file: look for end of filename
		for (pos2=pos+5;
		     pos2<value.length() && value.charAt(pos2)!=',' && value.charAt(pos2)!=' ' && value.charAt(pos2)!='\t';
		     pos2++);

		// Add value to the right dependency lists
		entry.addDependency(value.substring(pos+5,pos2));
	    } else {
		// Found unknown character at the start
		throw new ParseException(entry.name+": "+SUBJECT_KEY+" value invalid: "+value, pos);
	    }

	    // Skip all trailing white-space and commas
	    boolean foundComma=false;
	    for (pos=pos2; pos<value.length(); pos++)    {
		// Keep track of whether we found a comma: need at least one
		if (value.charAt(pos)==',') {
		    foundComma=true;
		    continue;
		}
		if (value.charAt(pos)!=' ' && value.charAt(pos)!='\t')
		    break;
	    }

	    // Did we hit the end-of-line or find a comment char?
	    if (pos==value.length() || value.charAt(pos)=='#')
		break;

	    // Not yet at end, did we see a comma?
	    if (!foundComma)
		throw new ParseException(entry.name+": Missing comma delimiter before new entry", pos);
	}
    }

    /**
     * Adds all the external dependencies from entry and add them to the given
     * infofilelist when not yet there.
     * @param entry input entry
     * @param extinfofiles ArrayList of Path to add the external dependencies to
     */
    private void addExtDeps(Entry entry, ArrayList<Path> extinfofiles)    {
	ArrayList<Path> extdeps=entry.extdeps;
	for (int i=0; i<extdeps.size(); i++)    {
	    Path extdep=extdeps.get(i);
	    if (!extinfofiles.contains(extdep))
		extinfofiles.add(extdep);
	}
    }

    /**
     * Search for entry in entries matching path
     * @param path Path to search for (needle)
     * @param entries list of Entry to search through (haystack)
     * @return Entry matching path or null when no match is found
     */
    private Entry getEntry(Path path, ArrayList<Entry> entries)	{
	for (int i=0; i<entries.size(); i++)    {
	    Entry entry = entries.get(i);
	    if (path.equals(entry.path))
		return entry;
	}
	return null;
    }

    ////////////////////////////////////////////////////////////////////////
    // Private class
    ////////////////////////////////////////////////////////////////////////

    /** Internal type of info file entries */
    private class Entry	{
	/** full path of this info file */
	Path path;
	/** name of this info entry (basename of info file) */
	String name;
	/** last modification time of this info file */
	FileTime modified;
	/** dependencies in the trust_dir */
	ArrayList<Path> deps;
	/** dependencies outside of the trust_dir */
	ArrayList<Path> extdeps;
	/** list of subject DNs defined directly in this file */
	ArrayList<String> localSubDNs;
	/** complete array of subject DNs for this info file */
	String[] subDNs;

	/**
	 * Constructor, setting name and modified from path.
	 * @param path path of the info file
	 */
	private Entry(Path path) {
	    try {
		this.modified=Files.getLastModifiedTime(path);
	    } catch (IOException e) { // Cannot initialize: use 1/1/1970
		this.modified=FileTime.fromMillis(0);
	    }
	    String name=path.getFileName().toString();
	    this.name = (name.endsWith(FILE_SFX)
		? name.substring(0, name.length()-FILE_SFX.length())
		: name);
	    this.path=path;
	    this.deps=new ArrayList<Path>();
	    this.extdeps=new ArrayList<Path>();
	    this.localSubDNs=new ArrayList<String>();
	}

	/**
	 * Resolves what type of dependency we have and add to the correct
	 * dependency list
	 * @param dependency Path of the dependency to find
	 * @throws IOException on filesystem errors
	 */
	private void addDependency(String dependency)
	    throws IOException
	{
	    // First get correct Path for the filename
	    Path deppath;
	    if (dependency.charAt(0) == '/')
		// absolute path
		deppath=Paths.get(dependency).normalize();
	    else if (dependency.indexOf('/')==-1)
		// no directory components, could still symlink to external
		deppath=Paths.get(trust_dir, dependency);
	    else
		// relative path
		deppath=Paths.get(trust_dir, dependency).normalize();
	    
	    // Resolve symlinks when needed
	    if (Files.isSymbolicLink(deppath))
		deppath=deppath.toRealPath();

	    // Add path to right dependency list
	    ArrayList<Path> deplist;
	    // If real path is in trust_dir *and* ends with the FILE_SFX,
	    // otherwise we consider it external
	    if (trust_dir.equals(deppath.getParent().toString()) &&
		deppath.getFileName().toString().endsWith(FILE_SFX))
		deplist=deps;
	    else
		deplist=extdeps;

	    // Add when not there yet
	    if (!deplist.contains(deppath))
		deplist.add(deppath);
	}

	/**
	 * Recursively retrieves all subject DNs for this entry, either defined
	 * locally or indirectly via dependencies.
	 * @return Array of String containing all the subject DNs
	 */
	private ArrayList<String> getSubDNs()	{
	    // Create temporary list
	    ArrayList<String> subDNsArr=new ArrayList<String>();

	    // Add all the local ones
	    subDNsArr.addAll(localSubDNs);

	    // Add all DNs from the deps list
	    for (int i=0; i<deps.size(); i++)	{
		Entry entry=getEntry(deps.get(i), infoEntries);
		if (entry!=null)
		    subDNsArr.addAll(entry.getSubDNs());
	    }

	    // Add all DNs from the extdeps list
	    for (int i=0; i<extdeps.size(); i++)    {
		Entry entry=getEntry(extdeps.get(i), extInfoEntries);
		if (entry!=null)
		    subDNsArr.addAll(entry.getSubDNs());
	    }

	    // Return resulting set as array of String
	    return subDNsArr;
	}

	/**
	 * Updates the String array of all subject DNs valid for this info file
	 */
	private void updateSubDNs()	{
	    this.subDNs=getSubDNs().toArray(new String[0]);
	}
    
    }
}
