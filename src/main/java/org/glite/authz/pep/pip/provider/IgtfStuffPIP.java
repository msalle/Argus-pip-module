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
// Rens Visser <rensv@nikhef.nl>
// NIKHEF Amsterdam, the Netherlands
// <grid-mw-security@nikhef.nl>

package org.glite.authz.pep.pip.provider;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;

import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.print.DocFlavor.URL;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang.StringUtils;

import org.bouncycastle.jcajce.provider.symmetric.AES.OFB;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

/**
 * @author Rens Visser
 * @version 1.0
 * @since 1.0
 * 
 *        The IGTF PIP uses a pre-extracted issuer DN from the incoming request.
 *        The PIP uses the Issuer DN to find info files containing the issuer
 *        DN. After finding the required *.info files, a XACML request is
 *        generated and send to the PEPD.
 */
public class IgtfStuffPIP extends AbstractPolicyInformationPoint {
	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(IgtfStuffPIP.class);

	/**
	 * Default String of the info files location: {@value}
	 */
	private final static String INFO_FILE_LOCATION = "/etc/grid-security/certificates/";

	/**
	 * Default String of issuer DN attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

	/**
	 * Default String of CA policy names attribute(s): {@value}
	 */
	private final static String POPULATE_REQUEST_ATTRIBUTE_IDENTIFIER = "http://authz-interop.org/xacml/subject/ca-policy-names";

	/**
	 * Contains a string of the certificate issuer DN.
	 */
	private static String CertificateIssuerDN;

	/**
	 * List of .info files to return to the PEPD.
	 */
	private static List<String> infoFilesToReturn = new ArrayList<String>();

	/**
	 * The constructor
	 * 
	 * @param pipid
	 *            String consisting of the identifier of the pip.
	 */
	public IgtfStuffPIP(String pipid) {
		super(pipid);

	}

	/** {@inheritDoc} */
	public boolean populateRequest(Request request) throws PIPProcessingException {
		boolean toApply = false;
		try {
			// Make the request editable and readable in other parts of the java
			// code.
			Set<Subject> subjects = request.getSubjects();

			// List of all files in the grid-security directory
			List<String> infoFilesAll = findAllInfoFiles();

			// List of the contents of a interesting info file
			List<String> infoFilesContents = null;
			String file = null;

			// Start iteration to find correct info files.
			for (Subject subject : subjects) {
				// Gets the Issuer DN from the subject and stores it in the
				// CerificateIssuerDN variable.
				CertificateIssuerDN = getIssuerDNFromSubject(subject);

				// Checks if the certificate issuer equals null, if it equals
				// null, skip the rest of the code and continue with a new loop.
				if (CertificateIssuerDN == null) {
					log.debug("Certificate issuer does not exist.");
					continue;
				}

				// Create the attributes to be send to PEPD.
				Attribute policyInformation = new Attribute(POPULATE_REQUEST_ATTRIBUTE_IDENTIFIER);
				policyInformation.setDataType(Attribute.DT_STRING);

				// Loop over all found info files.
				for (int i = 0; i < infoFilesAll.size(); i++) {
					// Use one specific info files
					file = infoFilesAll.get(i);

					// Get the contents of a infofile in variable called "file".
					infoFilesContents = assuranceFileCheck(file);

					for (int j = 0; j < infoFilesContents.size(); j++) {
						// Checks if contents of variable CertificateIssuerDN is
						// in the infoFileContents.
						if (infoFilesContents.get(j).contains(CertificateIssuerDN) == true) {
							// Add to request being send to the PEPD.
							policyInformation.getValues().add(file.replace(".info", ""));
							toApply = true;
						}
					}
				}
				// Actually adding all the information being send to the PEPD.
				subject.getAttributes().add(policyInformation);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return toApply;
	}

	/**
	 * Decode the URL in the String urlToDecode.
	 * 
	 * @param urlToDecode
	 *            The String to decode
	 * @return The decoded string
	 */
	private String urlDecode(String urlToDecode) {
		int index;

		//Loop over the urlToDecode string, check if % are present.
		while ((index = urlToDecode.indexOf('%')) != -1) {
			//Get the substring containing the encoded character.
			String subSTR = urlToDecode.substring(index + 1, index + 3);
			//Concatenate the decoded URL back together.
			urlToDecode = urlToDecode.substring(0, index) + (char) Integer.parseInt(subSTR, 16)
					+ urlToDecode.substring(index + 3);
		}
		//Return entire urlToDecode String.
		return urlToDecode;
	}

	/**
	 * Adds all .info files from the grid-security/certificates folder to the variable infoFilesAll. 
	 * As last the method returns a list containing Strings.
	 * 
	 *  @return A list of strings. The strings represent *.info file.
	 */
	private List<String> findAllInfoFiles() {
		List<String> infoFilesAll = new ArrayList<String>();
		try {
			DirectoryStream<Path> stream = Files.newDirectoryStream(Paths.get(INFO_FILE_LOCATION), "*.info");
			for (Path entry : stream) {
				if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
					infoFilesAll.add(entry.getFileName().toString());
				}
			}
		} catch (Exception e) {
			log.debug(e.getMessage());
		}
		return infoFilesAll;
	}

	/**
	 * Gathers the issuer DN from subject. Return the issuer DN
	 * when found, if not found the method returns null.
	 * 
	 * @param req
	 *            The request where the issuer DN is extracted from. from.
	 * @return A string with "failed" or the issuer DN.
	 */
	private String getIssuerDNFromSubject(Subject subject) {
		String str = null;
		Set<Attribute> atts = subject.getAttributes();

		for (Attribute att : atts) {
			if (att.getId().matches(ATTRIBUTE_IDENTIFIER) == true) {
				str = att.getValues().toString();
				str = str.replace("[", "");
				str = str.replace("]", "");
				return str.trim();
			}
		}
		return null;
	}

	/**
	 * Parses the file from the input String. Method searches for a line with
	 * "SubjectDN" and parses it.
	 * 
	 * @param fileName
	 *            The {@link String} of the file to parse.
	 * @throws IOException
	 *             Throws an exception when the file can't be passed.
	 */
	private List<String> assuranceFileCheck(String fileName) throws IOException {
		// String builder, used to build the return string.
		StringBuilder stringBuilder = new StringBuilder();
		// Open required info file.
		BufferedReader br = new BufferedReader(new FileReader(INFO_FILE_LOCATION + fileName));
		//Variable to store a single of text.
		String line;
		//Int variables to store occunrances in a string.
		int firstQuotePos = 0, nextQuotePos = 0;
		//Variable contains all content of a *.info file.
		List<String> infoFilesContents = new ArrayList<String>();

		// Loop where the return string is build in.
		while ((line = br.readLine()) != null) {
			if (checkStartsWithHashtag(line) == true) {
				continue;
			}

			if (line.contains("subjectdn") == true) {
				line = removeTrailingSlash(line);
				stringBuilder.append(line);
				continue;
			}

			line = removeTrailingSlash(line);
			char[] cararray = line.toCharArray();

			for (int i = 0; i < cararray.length; i++) {
				if (cararray[i] == '"' && firstQuotePos == nextQuotePos) {
					firstQuotePos = i;
				} else if (cararray[i] == '"' && firstQuotePos > nextQuotePos) {
					nextQuotePos = i;
					stringBuilder.append(line);
					firstQuotePos = nextQuotePos;
				}
			}

			firstQuotePos = 0;
			nextQuotePos = 0;
			infoFilesContents.add(urlDecode(stringBuilder.toString()));
		}

		br.close();
		return infoFilesContents;
	}

	/**
	 * Removes the trailing slash from the input {@link String} and returns the modified
	 * string.
	 * 
	 * @param inputString
	 *            The String where the trailing slash is removed from.
	 * @return The modified String
	 */
	private String removeTrailingSlash(String inputString) {
		StringBuilder toReturn = new StringBuilder(inputString);
		int i = inputString.lastIndexOf("\\");

		if (i != -1) {
			toReturn.deleteCharAt(i);
		}

		return toReturn.toString();
	}

	/**
	 * Checks if input string starts with a #, if yes return true else return
	 * false.
	 * 
	 * @param toSearchline
	 *            The {@link String} With a issuer DN is parsed for a #
	 * @return {@link Boolean}
	 */
	private boolean checkStartsWithHashtag(String toSearchline) {
		boolean toReturn = false;

		toSearchline = toSearchline.trim();

		for (int i = 0; i < toSearchline.length(); i++) {
			if (toSearchline.charAt(i) == '"') {
				toReturn = false;
				break;
			} else if (toSearchline.charAt(i) == '#') {
				toReturn = true;
				break;
			}
		}
		return toReturn;
	}
}