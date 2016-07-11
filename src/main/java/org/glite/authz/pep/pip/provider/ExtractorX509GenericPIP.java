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

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.util.encoders.Base64;

//import org.bouncycastle.asn1.x509.X509Extension;
//import org.bouncycastle.asn1.x509.Extension;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyUtils;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * @author Rens Visser
 * @version 1.0
 * @since 1.0
 * 
 *        The X509PIPPolicyOIDExtractor PIP extracts Policy OIDs and the issuer
 *        DN from incoming authorization requests. After extracting the required
 *        information, a existing XACML request is populated with the extracted
 *        information.
 * 
 *        PIP fails running when subjectid is used instead of Keyinfo.
 */
public class ExtractorX509GenericPIP extends AbstractPolicyInformationPoint {
	/**
	 * Class logger used for debugging.
	 */
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIP.class);

	/**
	 * String array of attribute(s) found in the incoming request that are
	 * accepted
	 */
	private String[] acceptedAttributes_ = null;

	/**
	 * Default String of CA policy OIDs attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER_CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

	/**
	 * Default String of Issuer DN attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

	/**
	 * Default String of key-info attribute(s): {@value}
	 */
	private final static String ATTRIBUTE_IDENTIFIER_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info";

	/**
	 * When acceptedAttributes is filled, then it makes the local variable
	 * acceptedAttributes_ available to the whole class. If acceptedAttributes
	 * is empty, an Exception is thrown and the PIP will not run.
	 *
	 * @param pipid
	 *            The PIP identifier name
	 * 
	 * @param acceptedAttributes
	 *            String array of accepted attributes.
	 * 
	 */
	public ExtractorX509GenericPIP(String pipid, String[] acceptedAttributes) {
		super(pipid);

		// Check to see if the String array String[] acceptedAttributes is not
		// empty.
		if (acceptedAttributes.length == 0) {
			new Exception("No accepted attributes have been supplied.");
		}

		acceptedAttributes_ = acceptedAttributes;
	}

	/**
	 * The method that does all the work. The Argus framework makes sure that
	 * when a PIP does apply to a request, the populateRequest(Request request)
	 * method is always run.
	 * 
	 * When the incoming request has no subjects then this PIP will NOT run.
	 * This PIP will throw an Exception when an attribute is not configured in
	 * the pepd.ini configuration file. This PIP takes an incoming request, it
	 * extracts the Issuer DN and the CA policy OIDs from the incoming request.
	 *
	 * 
	 * @param request
	 *            Request object containing all information of the incoming
	 *            request.
	 * 
	 * @throws PIPProcessingException
		      in case of errors
	 * 
	 * @return boolean
	 */
	public boolean populateRequest(Request request) throws PIPProcessingException {

	    log.debug("Starting PIP");

		// Declaration of used variables
		X509Certificate cert = null;
		Set<Subject> subjects = request.getSubjects();
		Set<Attribute> subjectAttributes = null;
		Boolean PIP_applied = false;

		// If subjects is empty, the PIP will not run.
		if (subjects.isEmpty()) {
			log.error("Request has no subject!");
			return false;
		}
	    log.debug("Found "+subjects.size()+" subjects");

		try {

			for (Subject subject : subjects) {
				String acceptedID = null;
				subjectAttributes = subject.getAttributes();
				log.debug("Found "+subjectAttributes.size()+" subjectAttributes");
				Attribute caPolicyOIDsInformation = new Attribute(ATTRIBUTE_IDENTIFIER_CA_POLICY_OID);
				caPolicyOIDsInformation.setDataType(Attribute.DT_STRING);

				Attribute issuerDNInformation = new Attribute(ATTRIBUTE_IDENTIFIER_X509_ISSUER);
				issuerDNInformation.setDataType(Attribute.DT_STRING);

				// Get the end-entity X509 certificate.
				cert = ProxyUtils.getEndUserCertificate(findPEMAttributeForConverson(subjectAttributes));
				if (cert == null)   {
				    log.error("Certificate is unset");
				    continue;
				}
				log.debug("Found cert");
				

				// Loop over each accepted attribute .
				for (int i = 0; i < acceptedAttributes_.length; i++) {
					acceptedID = acceptedAttributes_[i];
					log.debug("Trying attribute "+acceptedID);
					// Check if its an CA policy oid
					if (acceptedID.equals(ATTRIBUTE_IDENTIFIER_CA_POLICY_OID)) {
						PIP_applied = true;
						log.debug("Trying to get policy OIDs");
						List<String> policyOIDs = getPolicyOIDs(cert);
						log.debug("Found "+policyOIDs.size()+" OIDs");

						// List all found policy IDs
						for (String str : policyOIDs) {
							caPolicyOIDsInformation.getValues().add(str);
						}
						subjectAttributes.add(caPolicyOIDsInformation);

						// Check if its an Issuer DN
					} else if (acceptedID.equals(ATTRIBUTE_IDENTIFIER_X509_ISSUER)) {
						PIP_applied = true;
						String str = cert.getIssuerX500Principal().getName();
						log.debug("Found issuer DN "+str);
						// Grab, convert and store the Issuer DN.
						issuerDNInformation.getValues().add(OpensslNameUtils.convertFromRfc2253(str, false));
						subjectAttributes.add(issuerDNInformation);
						// If none of the above, abort!
					} else {
						log.error("Non-handled attribute specified in ini file: " + acceptedID);
						throw new Exception("Non-handled attribute specified in ini file: " + acceptedID);
					}
				}
			}
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new PIPProcessingException(e.getMessage());
			// e.printStackTrace();
		}

		return PIP_applied;
	}

	/**
	 * Gets the policy OIDs from a {@link X509Certificate} and returns a list of
	 * policy OIds in String object format.
	 * 
	 * @param cert
	 *            The x509Certificate where the Policy OID(s) are extracted
	 *            from.
	 * @return a List of String instance. The list is filled with Policy OIDs
	 *         strings.
	 * 
	 * @throws IOException
	 *             Thrown when readObject method does not work.
	 */
	@SuppressWarnings("resource") // Added to supres errors that are not useful
	protected List<String> getPolicyOIDs(X509Certificate cert) throws IOException {
		List<String> oidList = new LazyList<String>();

		String certPolicies = null;
/*		try {
		    Class<?> extension = Class.forName("org.bouncycastle.asn1.x509.Extension");
//		    java.lang.reflect.Field field = extension.getField("certificatePolicies");
//		    Object fieldvalue = field.get(extension);
//		    certPolicies = ((org.bouncycastle.asn1.ASN1ObjectIdentifier)fieldvalue).toString();
		    certPolicies = extension.getField("certificatePolicies").get(extension).toString();
		} catch (Exception e) { // NoSuchFieldException or ClassNotFoundException
		    certPolicies = org.bouncycastle.asn1.x509.X509Extension.certificatePolicies.toString();
		}*/
		certPolicies = org.bouncycastle.asn1.x509.X509Extension.certificatePolicies.toString();
		if (certPolicies == null)   {
		    log.error("certPolicies is null");
		    return null;
		}
		log.debug("Found certPolicies = "+certPolicies);

		log.debug("Found cert: "+cert.toString());

		byte[] extvalue = cert.getExtensionValue(certPolicies);

		if (extvalue == null) {
			log.warn("No valid certificate policies found!");
			return null;
		}
		log.debug("Found extvalue");

		// Convert extension blob into DER octet string
//		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
		log.debug("Found oct: "+oct==null ? "null" : "non-null");
		// ANS1 sequence generated from the DER octet string
		ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();
		log.debug("Found seq: "+seq==null ? "null" : "non-null");

		/* Loop over all policy OIDs */
		for (int pos = 0; pos < seq.size(); pos++) {
			if (PolicyInformation.getInstance(seq.getObjectAt(pos)).getPolicyIdentifier().getId() != null) {
				oidList.add(PolicyInformation.getInstance(seq.getObjectAt(pos)).getPolicyIdentifier().getId());
			} else {
				log.error("Policy does not exist!");
				throw new IOException("Policy does not exist!");
			}
		}

		return oidList;
	}

	/**
	 * Creates a X509Certificate chain from a Attribute indicated by element
	 * from a Set of Attributes. Does this by finding the Attribute ID
	 * corresponding to the required attribute. Quits PIP when no PEM string is
	 * found in the content. The incoming request must have a
	 * urn:oasis:names:tc:xacml:1.0:subject:key-info attribute, if not quits the
	 * PIP.
	 *
	 * @param attributes
	 *            A {@link Set} filled with {@link Attribute}
	 * 
	 * @return a X509Certificate[] objects instance
	 * @throws PIPProcessingException in case of error
	 * @throws CertificateException when
	 * @throws KeyStoreException when
	 * @throws IOException when
	 */
	protected X509Certificate[] findPEMAttributeForConverson(Set<Attribute> attributes)
			throws CertificateException, KeyStoreException, IOException, PIPProcessingException {
//			throws PIPProcessingException {
		X509Certificate[] certificateChain = null;
		boolean hasExecuted = false;
		String checkThisStr = null;

		if (attributes.size() < 1) {
			throw new PIPProcessingException("Request without subject element!");
		}

		// Contains all certificates as a string
		for (Attribute attribute : attributes) {
			// Check whether the attribute ID is
			// "urn:oasis:names:tc:xacml:1.0:subject:key-info". When true
			// execute, else continue to next element.
			if (attribute.getId().equals(ATTRIBUTE_IDENTIFIER_KEY_INFO)) {
				Set<Object> attributeValues = attribute.getValues();
				// Used for other values
				for (Object attributeValue : attributeValues) {

					// Checks if string contains pem formatted content
					try {
						checkThisStr = (String) attributeValue;
						if (!isPEMString(checkThisStr)) {
							checkThisStr = getCorrectPEMStingFromMallFormedPemString(checkThisStr);
						}
						certificateChain = pemConvertToX509CertificateChain(checkThisStr);
						if (certificateChain.length == 0)
						    throw new PIPProcessingException("Empty certificate chain");
						hasExecuted = true;
					} catch (Exception e) {
						throw new PIPProcessingException("The PEM string is not correct!");
					}
				}
			}
		}

		if (hasExecuted == false) {
			throw new PIPProcessingException(
					"No pem String content in request! PIP ExtractorX509GenericPIP quited running...");
		}
		return certificateChain;
	}

	/**
	 * Converts a PEM String to a X509Certificate object array. Utterly fails
	 * and throws an exception when NO PEM String is provided.
	 *
	 * @param pem
	 *            A PEM formatted String
	 * @return a X509Certificate[] chain
	 * 
	 * @throws IOException when
	 * @throws KeyStoreException when
	 * @throws CertificateException when
	 */
	private X509Certificate[] pemConvertToX509CertificateChain(String pem)
			throws CertificateException, IOException, KeyStoreException {
		// Convert string to a UTF-8 encoded InputStream PEM object.
		InputStream pemReader = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
		// Convert InputStream PEM object to X509certificate object chain
		return CertificateUtils.loadCertificateChain(pemReader, Encoding.PEM);
	}

	private Boolean isPEMString(String str) {
		if (str.contains("-----BEGIN CERTIFICATE-----")) {
			return true;
		}
		return false;
	}

	private String getCorrectPEMStingFromMallFormedPemString(String str) {
		StringBuilder strBuilder = new StringBuilder();
		String[] strArray = null;
		strArray = str.split(",");

		for (String strTMP : strArray) {
			strBuilder.append("-----BEGIN CERTIFICATE-----\n" + strTMP + "\n-----END CERTIFICATE-----");
		}

		return strBuilder.toString();
	}
}
