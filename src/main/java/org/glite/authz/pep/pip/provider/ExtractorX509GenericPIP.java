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
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.Extension;

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
 * 
 *         The X509PIPPolicyOIDExtractor PIP extracts Policy OIDs from incoming
 *         authorization requests. After extracting a XACML request is generated
 *         and send to the PEPD.
 */
public class ExtractorX509GenericPIP extends AbstractPolicyInformationPoint {
	/**
	 * Class logger used for debugging.
	 */
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIP.class);

	/**/
	private String[] acceptedAttributes_ = null;

	/**
	 * Default String of CA policy OIDs attribute(s): {@value}
	 */
	public final static String ATTRIBUTE_IDENTIFIER_CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

	/**
	 * Default String of Issuer DN attribute(s): {@value}
	 */
	public final static String ATTRIBUTE_SUBJECT_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

	/**
	 * Constructor. if acceptedAttributes is filled, then it makes the local variable available to the whole class.
	 * If acceptedAttributes is empty, an Exception is thrown and the PIP will not run.
	 *
	 * @param pipid
	 *            The PIP identifier name
	 * 
	 * @param acceptedAttributes
	 *            String array of accepted attributes.
	 * @throws Exception
	 */
	public ExtractorX509GenericPIP(String pipid, String[] acceptedAttributes) {
		super(pipid);

		if (acceptedAttributes.length == 0) {
			new Exception("No accepted attributes have been supplied.");
		}

		acceptedAttributes_ = acceptedAttributes;
	}

	/** {@inheritDoc} */
	public boolean populateRequest(Request request) throws PIPProcessingException {
		X509Certificate cert = null;
		// boolean toApplyPIP = true;
		Set<Subject> subjects = request.getSubjects();
		Set<Attribute> subjectAttributes = null;

		int debugI = 0;

		if (subjects.isEmpty()) {
			log.debug("Request has no subject!");
			return false;
		}

		try {

			for (Subject subject : subjects) {
				String acceptedID = null;
				subjectAttributes = subject.getAttributes();
				Attribute caPolicyOIDsInformation = new Attribute(ATTRIBUTE_IDENTIFIER_CA_POLICY_OID);
				caPolicyOIDsInformation.setDataType(Attribute.DT_STRING);

				Attribute issuerDNInformation = new Attribute(ATTRIBUTE_SUBJECT_X509_ISSUER);
				issuerDNInformation.setDataType(Attribute.DT_STRING);

				// Get the end-entity X509 certificate.
				cert = ProxyUtils.getEndUserCertificate(findPEMAttributeForConverson(subjectAttributes, "Subject"));

				// Loop over each accepted attribute .
				for (int i = 0; i < acceptedAttributes_.length; i++) {
					acceptedID = acceptedAttributes_[i];

					// Check if its an CA policy oid
					if (acceptedID.equals(ATTRIBUTE_IDENTIFIER_CA_POLICY_OID)) {
						List<String> policyOIDs = getPolicyOIDs(cert);

						for (String str : policyOIDs) {
							caPolicyOIDsInformation.getValues().add(str);
						}
						subjectAttributes.add(caPolicyOIDsInformation);

						// Check if its an Issuer DN
					} else if (acceptedID.equals(ATTRIBUTE_SUBJECT_X509_ISSUER)) {
						String str = cert.getIssuerX500Principal().getName();
						issuerDNInformation.getValues().add(OpensslNameUtils.convertFromRfc2253(str, false));
						subjectAttributes.add(issuerDNInformation);
						// If none of the above, abort!
					} else {
						throw new Exception("Non-handled attribute specified in ini file: " + acceptedID);
					}
				}
				log.debug("DebugI value: {}", debugI);
				debugI++;
			}
		} catch (Exception e) {
			log.debug(e.getMessage());
			e.printStackTrace();
		}

		return true;
	}

	/**
	 * Gets the policy OIDs from a {@link X509Certificate} and returns a list of
	 * string instances.
	 * 
	 * @param cert
	 *            The x509Certificate where the Policy OID(s) are extracted
	 *            from.
	 * @return a List<String> instance. The list is filled with Policy OIDs strings.
	 * @throws IOException
	 */
	@SuppressWarnings("resource") // Added to restrict umeaningful errors
	private List<String> getPolicyOIDs(X509Certificate cert) throws IOException {
		List<String> oidList = new LazyList<String>();
		StringBuilder debugSTR = new StringBuilder();

		byte[] extvalue = cert.getExtensionValue(Extension.certificatePolicies.toString());

		if (extvalue == null) {
			log.debug("No valid certificate policies found!");
			return null;
		}

		// Convert extension blob into DER octet string
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
		// ANS1 sequence generated from the DER octet string
		ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();

		/* Loop over all policy OIDs */
		for (int pos = 0; pos < seq.size(); pos++) {
			if (PolicyInformation.getInstance(seq.getObjectAt(pos)).getPolicyIdentifier().getId() != null) {
				oidList.add(PolicyInformation.getInstance(seq.getObjectAt(pos)).getPolicyIdentifier().getId());
				debugSTR.append(
						PolicyInformation.getInstance(seq.getObjectAt(pos)).getPolicyIdentifier().getId() + "/r");
			} else {
				throw new IOException("Policy does not exist!");
			}
		}

		log.debug("Found policies: {}", debugSTR.toString());
		return oidList;
	}

	/**
	 * Creates a X509Certificate chain from a Attribute indicated by element
	 * from a Set of Attributes. Does this by finding the Attribute corresponding to the element.
	 *
	 * @param attributes
	 *            A {@link Set} filled with {@link Attribute}
	 * 
	 * @param element
	 *            What element to get
	 * @return a X509Certificate[] objects instance
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws PIPProcessingException
	 */
	private static X509Certificate[] findPEMAttributeForConverson(Set<Attribute> attributes, String element)
			throws CertificateException, KeyStoreException, IOException, PIPProcessingException {
		X509Certificate[] pemChain = null;
		if (attributes.size() < 1) {
			throw new PIPProcessingException("Decision request " + element + " without any chain!");
		}
		// Contains all certificates as a string
		for (Attribute attribute : attributes) {
			Set<Object> attributeValues = attribute.getValues();
			// Used for other values
			for (Object attributeValue : attributeValues) {
				pemChain = pemConvertToX509CertificateChain(attributeValue.toString());
			}
		}
		return pemChain;
	}

	/**
	 * Converts a PEM formatted String to a {@link X509Certificate} instances
	 * array.
	 *
	 * @param pem
	 *            A PEM formatted String
	 * @return a X509Certificate[] chain
	 */
	public static X509Certificate[] pemConvertToX509CertificateChain(String pem)
			throws CertificateException, IOException, KeyStoreException {
		// Convert string to a UTF-8 encoded InputStream PEM object.
		InputStream pemReader = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
		// Convert InputStream PEM object to X509certificate object chain
		return CertificateUtils.loadCertificateChain(pemReader, Encoding.PEM);
	}
}