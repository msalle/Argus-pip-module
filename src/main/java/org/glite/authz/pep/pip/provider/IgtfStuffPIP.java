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
 * 
 *         The IGTF PIP extracts the issuer DN from the incomming request. IT
 *         then searches all info files to find the required info file(s).
 */
public class IgtfStuffPIP extends AbstractPolicyInformationPoint {
	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(IgtfStuffPIP.class);

	private final static String INFO_FILE_LOCATION = "/etc/grid-security/certificates/";
	private final static String ATTRIBUTE_IDENTIFIER = "http://example.org/xacml/subject/ca-policy-names";

	/**
	 * Contains a string of the certificate issuer DN.
	 */
	private static String CertificateIssuerDN;

	/**
	 * Contains all info files
	 */
	private static List<String> infoFilesAll = new ArrayList<String>();

	/**
	 * List of .info files to return.
	 */
	private static List<String> infoFilesToReturn = new ArrayList<String>();

	/**
	 * Contains the content of matching .info files.
	 */
	private static List<String> infoFilesContents = new ArrayList<String>();

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
			// Make the request editable and readable in other java code.
			Set<Subject> subjects = request.getSubjects();
			// Get the Certificate issuer DN and store it in a class wide
			// variable.
			CertificateIssuerDN = urlDecodeIssuerDNCertificate(getIssuerDNCertificateFromIncommingRequest(request));

			if (CertificateIssuerDN.contains("failed") == false) {
				toApply = true;
				// find ALL .info files.
				findAllInfoFiles();

				// Start iteration to find correct info files.
				for (Subject subject : subjects) {
					// Create the attributes to be send to PEPD.
					Attribute policyInformation = new Attribute(ATTRIBUTE_IDENTIFIER);
					policyInformation.setDataType(Attribute.DT_STRING);

					for (int i = 0; i < infoFilesAll.size(); i++) {
						assuranceFileCheck(infoFilesAll.get(i));

						if (infoFilesContents.get(i).contains(CertificateIssuerDN) == true) {
							policyInformation.getValues().add(infoFilesAll.get(i).replace(".info", ""));
						}
					}
					subject.getAttributes().add(policyInformation);
				}
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return toApply;
	}

	/**
	 * URL Encodes the input String.
	 * 
	 * @param urlToEncode
	 *            The String to encode
	 * @return The encoded string
	 */
	private static String urlEncodeIssuerDNCertificate(String urlToEncode) {
		StringBuilder strBuilder = new StringBuilder();

		urlToEncode = urlToEncode.replace("#", "%23");
		urlToEncode = urlToEncode.replace("\"", "%22");
		urlToEncode = urlToEncode.replace("\\", "%5c");

		return urlToEncode;
	}

	/**
	 * URL decodes the input String.
	 * 
	 * @param urlToDecode
	 *            The String to decode
	 * @return The decoded string
	 */
	private static String urlDecodeIssuerDNCertificate(String urlToDecode) {
		StringBuilder strBuilder = new StringBuilder();

		urlToDecode = urlToDecode.replace("%23", "#");
		urlToDecode = urlToDecode.replace("%22", "\"");
		urlToDecode = urlToDecode.replace("%5c", "\\");

		return urlToDecode;
	}

	/**
	 * Adds all .info files from the grid-security/certifiactes folder
	 */
	private void findAllInfoFiles() {
		File folder = new File(INFO_FILE_LOCATION);
		File[] listOfFiles = folder.listFiles();
		String extension = null;

		for (File file : listOfFiles) {
			extension = file.getName().substring(file.getName().lastIndexOf(".") + 1, file.getName().length());
			if (file.isFile() && extension.equals("info")) {
				infoFilesAll.add(file.getName());
			}
		}
	}

	/**
	 * Gathers the issuer DN from the incoming request. Return the issuer DN
	 * when found, if not found the method returns "failed"
	 * 
	 * @param req
	 *            The request where the issuer DN is extracted from. from.
	 * @return A string with "failed" or the issuer DN.
	 */
	private String getIssuerDNCertificateFromIncommingRequest(Request req) {
		String str = null;
		Set<Subject> subjects = req.getSubjects();

		for (Subject subject : subjects) {
			Set<Attribute> atts = subject.getAttributes();

			for (Attribute att : atts) {
				if (att.getValues().toString().contains("CN=") || att.getValues().toString().contains("cn=")) {
					return att.getValues().toString();
				}
			}
		}

		return "failed";
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
	private void assuranceFileCheck(String fileName) throws IOException {
		//String builder, used to build the return string.
		StringBuilder stringBuilder = new StringBuilder();
		//Open required info file.
		BufferedReader br = new BufferedReader(new FileReader(INFO_FILE_LOCATION + fileName));
		String line;
		int firstQuotePos = 0, nextQuotePos = 0;

		//Loop where the return string is build in.
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
		}

		infoFilesContents.add(urlDecodeIssuerDNCertificate(stringBuilder.toString()));
		br.close();
	}

	/**
	 * Removes the trailing slash from the input {@link String} and the modified
	 * string.
	 * 
	 * @param inputString
	 *            The String where the trailing slash is removed from.
	 * @return String
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