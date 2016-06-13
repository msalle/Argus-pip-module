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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 *        The InInfoFileIssuerDNMatcher PIP uses a pre-extracted issuer DN from
 *        the incoming request. The PIP uses the Issuer DN to find info files
 *        containing the issuer DN. After finding the required *.info files, the
 *        XACML request is populated and can be used by the PEPD.
 */
public class InInfoFileIssuerDNMatcher extends AbstractPolicyInformationPoint {
	/**
	 * Class logger.
	 */
	private final Logger log = LoggerFactory.getLogger(InInfoFileIssuerDNMatcher.class);

	/**
	 * Default String of issuer DN attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

	/**
	 * Default String of CA policy names attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER_CA_POLICY_NAMES = "http://authz-interop.org/xacml/subject/ca-policy-names";

	/**
	 * Contains a string of the certificate issuer DN.
	 */
	protected static String CertificateIssuerDN;

	/**
	 * Contains a string of trusted .info file and certificates location.
	 */
	private static String acceptedtrustInfoDir;

	/**
	 * The constructor
	 * 
	 * @param pipid
	 *            String consisting of the identifier of the pip.
	 */
	public InInfoFileIssuerDNMatcher(String pipid, String acceptedtrustInfoDirLocal) {
		super(pipid);

		if (!acceptedtrustInfoDirLocal.endsWith("//")) {
			acceptedtrustInfoDirLocal = acceptedtrustInfoDirLocal + "//";
		}

		acceptedtrustInfoDir = acceptedtrustInfoDirLocal;
	}

	/**
	 * When the incoming request has no subjects then this PIP will NOT run.
	 * This PIP will throw an Exception when CertificateIssuerDN is empty. This
	 * PIP takes an incoming request, it extracts the Issuer DN incoming
	 * request. The extracted issuer DN is then compared to certificate issuer
	 * in all *.info files on the server. This PIP fails when, there are no info
	 * files.
	 *
	 * The method that does all the work. The Argus framework makes sure that
	 * when a PIP does apply to a request, the populateRequest(Request request)
	 * method is always run.
	 * 
	 * @param request
	 *            Request object containing all information of the incoming
	 *            request.
	 * 
	 * @throws PIPProcessingException
	 *             Thrown when a unexpected error occurs.
	 * 
	 * @return boolean
	 */
	/** {@inheritDoc} */
	public boolean populateRequest(Request request) throws PIPProcessingException {
		boolean PIP_applied = false;
		try {
			// Make the request editable and readable in other parts of the java
			// code.
			Set<Subject> subjects = request.getSubjects();
			// List of all files in the grid-security directory
			List<String> allInfoFiles = findAllInfoFiles();
			String file = null;

			if (allInfoFiles == null || allInfoFiles.size() == 0) {
				throw new PIPProcessingException("No info files!");
			}

			if (subjects.isEmpty()) {
				throw new PIPProcessingException("No subject found in request!!");
			}

			// Start iteration to find correct info files.
			for (Subject subject : subjects) {
				// Gets the Issuer DN from the subject and stores it in the
				// CerificateIssuerDN variable.
				CertificateIssuerDN = getIssuerDNFromSubject(subject.getAttributes());
				// CertificateIssuerDN = (CertificateIssuerDN);
				// Checks if the certificate issuer equals null, if it equals
				// null, skip the rest of the code and continue with a new loop.
				if (CertificateIssuerDN == null) {
					throw new Exception("Certificate issuer attribute is not set");
				}

				// Create the attributes to be send to PEPD.
				Attribute policyInformation = new Attribute(ATTRIBUTE_IDENTIFIER_CA_POLICY_NAMES);
				policyInformation.setDataType(Attribute.DT_STRING);
				log.debug("allInfoFiles.size() = " + allInfoFiles.size());
				// Loop over all found info files.
				for (int i = 0; i < allInfoFiles.size(); i++) {
					// Use one specific info files
					file = allInfoFiles.get(i);

					// Matches CertificateIssuerDN to contents if info file
					// specified in "file".
					log.debug("File: " + file);
					if (issuerDNParser(file)) {
						PIP_applied = true;

						policyInformation.getValues().add(file.replace(".info", ""));
					}
				}
				// Actually adding all the information being send to the PEPD.
				subject.getAttributes().add(policyInformation);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return PIP_applied;
	}

	/**
	 * Decodes the URL in the String urlToDecode.
	 * 
	 * @param urlToDecode
	 *            The String to decode
	 * @return The decoded string
	 */
	private String urlDecode(String urlToDecode) {
		int index;

		// Loop over the urlToDecode string, check if % are present.
		while ((index = urlToDecode.indexOf('%')) != -1) {
			// Get the substring containing the encoded character.
			String subSTR = urlToDecode.substring(index + 1, index + 3);
			// Concatenate the decoded URL back together.
			urlToDecode = urlToDecode.substring(0, index) + (char) Integer.parseInt(subSTR, 16)
					+ urlToDecode.substring(index + 3);
		}
		// Return entire urlToDecode String.
		return urlToDecode;
	}

	/**
	 * Adds all .info files from the grid-security/certificates folder to the
	 * variable infoFilesAll. As last the method returns a list containing
	 * Strings. The Strings contain all *.info files.
	 * 
	 * @return A list of strings. The strings represent *.info file.
	 */
	private List<String> findAllInfoFiles() throws IOException {
		List<String> infoFilesAll = new ArrayList<String>();
		DirectoryStream<Path> stream = null;
		try {
			stream = Files.newDirectoryStream(Paths.get(acceptedtrustInfoDir), "*.info");
		} catch (Exception e) {
			log.error(e.getMessage());
			return infoFilesAll;
		}

		try {
			for (Path entry : stream) {
				if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
					infoFilesAll.add(entry.getFileName().toString());
				}
			}

		} catch (Exception e) {
			log.error(e.getMessage());
		} finally {
			stream.close();
		}

		return infoFilesAll;
	}

	/**
	 * Gathers the issuer DN from Attributes. Return the issuer DN when found,
	 * if not found the method returns null.
	 * 
	 * @param attributes
	 *            The request where the issuer DN is extracted from. from.
	 * @return A string with "failed" or the issuer DN.
	 */
	protected String getIssuerDNFromSubject(Set<Attribute> attributes) {
		StringBuilder strBuilder = new StringBuilder();
		for (Attribute att : attributes) {
			if (att.getId().matches(ATTRIBUTE_IDENTIFIER_X509_ISSUER) == true) {
				strBuilder.append(att.getValues().iterator().next());
				log.debug(ATTRIBUTE_IDENTIFIER_X509_ISSUER + " = " + strBuilder.toString().trim());
				return strBuilder.toString().trim();
			}
		}
		return null;
	}

	/**
	 * Parses the file from the input String. Method parses all lines in the
	 * .info file. All lines are parsed one by one. Checks if line ends with a
	 * "\" if yes, remove the slash. Checks if line contains hask. If yes,
	 * removes the # and all text behind it. Returns true if info file is found,
	 * false otherwise.
	 * 
	 * @param fileName
	 *            The {@link String} of the file to parse.
	 * @throws IOException
	 *             Throws an exception when the file can't be passed.
	 * 
	 * @throws Exception
	 *             Thrown when file descriptor does not close properly
	 */
	protected Boolean issuerDNParser(String fileName) throws IOException, Exception {
		StringBuilder stringBuilder = new StringBuilder();
		FileReader readerFile = new FileReader(acceptedtrustInfoDir + fileName);
		BufferedReader br = new BufferedReader(readerFile);
		String contentLine = null;
		Pattern pattern = Pattern.compile("^subjectdn\\s*=\\s*");

		try {
			while ((contentLine = br.readLine()) != null) {
				if (contentLine.contains("#")) {
					contentLine = removeHashAndRestOfline(contentLine);
					contentLine.contains("contentLine = " + contentLine);
					if (contentLine.isEmpty()) {
						continue;
					}
				}

				if (contentLine.endsWith("\\")) {
					contentLine = removeTrailingSlash(contentLine);
					stringBuilder.append(contentLine);
					continue;

				} else {
					stringBuilder.append(contentLine);
					contentLine = stringBuilder.toString();
					stringBuilder = new StringBuilder();
				}

				contentLine = contentLine.trim();
				if (pattern.matcher(contentLine).lookingAt() && !contentLine.isEmpty()) {
					contentLine = contentLine.replaceFirst("^(subjectdn(\\s)*=(\\s)*)", "");
					return issuerDNMatcher(contentLine);
				}
			}
		} catch (Exception e) {
			log.debug(e.getMessage());
		} finally {
			br.close();
		}
		return false;
	}

	/**
	 * Matches all lines till known issuerDN and the searched issuerDN are
	 * matched. After the match either a true on success, or false on failure is
	 * returned. Splits the string into an array, the array is then searched.
	 * 
	 * @param input
	 *            String to be checked.
	 * @return Boolean true on success, false on failure.
	 */
	private Boolean issuerDNMatcher(String input) {
		String[] issuerDNInfoFileArray = input.split("(?<=\\\"),");
		String decodedCertificateIssuerDN;
		for (int b = 0; b < issuerDNInfoFileArray.length; b++) {
			decodedCertificateIssuerDN = urlDecode(issuerDNInfoFileArray[b].trim());
			if (decodedCertificateIssuerDN.matches("\"" + CertificateIssuerDN + "\"")) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Removes the "#" and everything behind the "#" from the input string.
	 * 
	 * @param input
	 *            The String to be modified.
	 * @return String The modified string.
	 */
	private String removeHashAndRestOfline(String input) {
		int i = input.indexOf("#");

		if (i == 0) {
			return "";
		} else {
			return input.substring(0, i - 1);
		}
	}

	/**
	 * Removes the trailing slash from the input {@link String} and returns the
	 * modified string.
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
}