// Copyright (c) FOM-Nikhef 2015-2016
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
// 2015-2016
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Rens Visser
 * 
 *         The X509PIPPolicyOIDExtractor PIP extracts Policy OIDs from incoming
 *         authorization requests. After extracting a XACML request is generated
 *         and send to the PEPD.
 */
public class ExtractorX509GenericPIP extends AbstractPolicyInformationPoint {
	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIP.class);

	/** List of subject attribute datatypes what must be converted */
	@SuppressWarnings("unused")
	private List<String> policyOidData_ = null;
	private List<String> acceptedProfileIds_ = null;
	/**
	 * Default list of subject attribute IDs what must be converted: {@value}
	 */
	public final static List<String> DEFAULT_POLICY_CA_OID_IDS = Arrays.asList();

	/**
	 * Default String of CA policy OIDs attribute(s): {@value}
	 */
	public final static String ATTRIBUTE_IDENTIFIER_CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

	public final static String ATTRIBUTE_SUBJECT_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

	/**
	 * Constructor.
	 *
	 * @param pipid
	 *            The PIP identifier name
	 */
	public ExtractorX509GenericPIP(String pipid, String[] acceptedProfileIds) {
		super(pipid);

		acceptedProfileIds_ = new ArrayList<String>(Arrays.asList(acceptedProfileIds));
	}

	/** {@inheritDoc} */
	public boolean populateRequest(Request request) throws PIPProcessingException {
		X509Certificate[] pemChain = null;
		X509Certificate cert = null;

		Set<Subject> subjects = request.getSubjects();

		try {

			for (Subject subject : subjects) {
				Attribute caPolicyOIDsInformation = new Attribute(getATTRIBUTE_IDENTIFIER_CA_POLICY_OID());
				caPolicyOIDsInformation.setDataType(Attribute.DT_STRING);
				
				Attribute issuerDNInformation = new Attribute(getATTRIBUTE_SUBJECT_X509_ISSUER());
				issuerDNInformation.setDataType(Attribute.DT_STRING);

				String acceptedID = null;

				pemChain = AttributeToX509CertificateChain(subject.getAttributes(), "Subject");

				cert = getEndUserCertificate(pemChain);

				for (int i = 0; i < acceptedProfileIds_.size(); i++) {
					acceptedID = acceptedProfileIds_.get(i);

					if (acceptedID.equals(getATTRIBUTE_IDENTIFIER_CA_POLICY_OID())) {
						List<String> policyOIDs = getOIDPolicies(cert);

						for (String str : policyOIDs) {
							caPolicyOIDsInformation.getValues().add(str);
						}
						subject.getAttributes().add(caPolicyOIDsInformation);

					} else if (acceptedID.equals(getATTRIBUTE_SUBJECT_X509_ISSUER())) {
						issuerDNInformation.getValues().add(OpensslNameUtils.convertFromRfc2253(cert.getIssuerX500Principal().getName(), false));
						subject.getAttributes().add(issuerDNInformation);
						log.debug("issuerDNInformation: {}", issuerDNInformation);
					}

				}

			}
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// return true;
		return true;
	}

	/**
	 * Gets the policy OIDs from a {@link X509Certificate} and returns a list of
	 * string instances.
	 * 
	 * @param cert
	 *            The x509Certificate where the Policy OID(s) are extracted
	 *            from.
	 * @return a List<String> instance
	 * @throws IOException
	 */
	@SuppressWarnings("resource")
	private List<String> getOIDPolicies(X509Certificate cert) throws IOException {
		List<String> policy = new LazyList<String>();

		byte[] extvalue = cert.getExtensionValue(Extension.certificatePolicies.toString());

		if (extvalue == null) {
			log.debug("EXTvalue = {}", extvalue);
			return null;
		}

		// Convert extension blob into DER octet string
		DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
		// ANS1 sewuence generated from the DER octet string
		ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();

		/* Loop over all policy OIDs */
		for (int pos = 0; pos < seq.size(); pos++) {
			PolicyInformation pol = PolicyInformation.getInstance(seq.getObjectAt(pos));
			policy.add(pol.getPolicyIdentifier().getId());
			log.debug("quatro Policy: {}", policy);
		}

		return policy;
	}

	/**
	 * Gets from an {@link X509Certificate} object array instance the End-Entity
	 * {@link X509Certificate} object instance
	 *
	 * @param certChain
	 *            The X509Certificate[] array to be extracted
	 * @return A X509Certificate object instance
	 */
	@SuppressWarnings("static-access")
	private X509Certificate getEndUserCertificate(X509Certificate[] certChain) {
		ProxyUtils proxyUtils = new ProxyUtils();

		if (!proxyUtils.getEndUserCertificate(certChain).equals(null))
			return proxyUtils.getEndUserCertificate(certChain);
		return null;
	}

	/**
	 * Converts a PEM formatted String to a {@link X509Certificate} instances
	 * array.
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
	private X509Certificate[] AttributeToX509CertificateChain(Set<Attribute> attributes, String element)
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
				// cert = convertToPemObject(value);
				pemChain = convertToPemObject(attributeValue.toString());
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
	 * @return a PemObject instance
	 */
	@SuppressWarnings("static-access")
	public X509Certificate[] convertToPemObject(String pem)
			throws CertificateException, IOException, KeyStoreException {
		CertificateUtils ChainPem = new CertificateUtils();

		InputStream pr = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
		return ChainPem.loadCertificateChain(pr, Encoding.PEM);
	}

	/**
	 * Getter method to get contents of @ATTRIBUTE_IDENTIFIER_CA_POLICY_OID
	 * identifier.
	 * 
	 * @return a {@link String}
	 */
	public String getATTRIBUTE_IDENTIFIER_CA_POLICY_OID() {
		return ATTRIBUTE_IDENTIFIER_CA_POLICY_OID;
	}

	/**
	 * Getter method to get contents of @ATTRIBUTE_SUBJECT_X509_ISSUER
	 * identifier.
	 * 
	 * @return a {@link String}
	 */
	public String getATTRIBUTE_SUBJECT_X509_ISSUER() {
		return ATTRIBUTE_SUBJECT_X509_ISSUER;
	}
}