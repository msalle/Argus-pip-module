//# Copyright (c) FOM-Nikhef 2015-
//# 
//# Licensed under the Apache License, Version 2.0 (the "License");
//# you may not use this file except in compliance with the License.
//# You may obtain a copy of the License at
//#
//#     http://www.apache.org/licenses/LICENSE-2.0
//#
//# Unless required by applicable law or agreed to in writing, software
//# distributed under the License is distributed on an "AS IS" BASIS,
//# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//# See the License for the specific language governing permissions and
//# limitations under the License.
//#
//# Authors:
//# 2015-
//#   Rens Visser <rensv@nikhef.nl>
//#    NIKHEF Amsterdam, the Netherlands
//#    <grid-mw-security@nikhef.nl>
//#

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Set;

import javax.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.X509CertificateObject;
import eu.emi.security.authn.x509.helpers.pkipath.NonValidatingCertPathBuilder;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

/**
 * Created by rens on 9-2-16.
 */
public class RensX509PIP extends AbstractPolicyInformationPoint {
	/** Class logger. */
	private final Logger log = LoggerFactory.getLogger(RensX509PIP.class);

	/** List of subject attribute datatypes what must be converted */
	private List<String> policyOidData_ = null;

	/**
	 * Default list of subject attribute IDs what must be converted: {@value}
	 */
	public final static List<String> DEFAULT_POLICY_OID_IDS = Arrays.asList();

	/**
	 * Constructor.
	 *
	 * @param pipid
	 *            The PIP identifier name
	 */
	public RensX509PIP(String pipid) {
		super(pipid);
	}

	/** {@inheritDoc} */
	public boolean populateRequest(Request request) throws PIPProcessingException {
		java.security.cert.X509Certificate[] pemChain = null;
		java.security.cert.X509Certificate cert = null;
		
		Set<Subject> subjects = request.getSubjects();
		for (Subject subject : subjects) {
			Attribute policyInformation= new Attribute("http://authz-interop.org/xacml/subject/ca-policy-oid");
			policyInformation.setDataType(Attribute.DT_STRING);
			
			pemChain = AttributeToX509CertificateChain(subject.getAttributes(), "Subject");
			cert = getEndUserCertificate(pemChain);
			List<String> tempForVar = getOIDPolicies(cert);
			log.debug("quatro tempForVar.size(): {}", tempForVar.size());
			 
			for (String str : tempForVar){
		        policyInformation.getValues().add(str);
				
			}
			subject.getAttributes().add(policyInformation);
		}

		return true;
	}
	
	private List<String> getOIDPolicies(java.security.cert.X509Certificate cert){
//X509CertificateObject eec = (X509CertificateObject)cert;
		 List<String> policy = new LazyList<String>();
		 
		byte[] extvalue = cert.getExtensionValue(Extension.certificatePolicies.toString());

		if(extvalue == null){
			log.debug("EXTvalue = {}", extvalue);
			return null;
		}
		
		try {
			//Convert extension blob into DER octet string
			DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
			//ANS1 sewuence generated from the DER octet string
			ASN1Sequence seq = (ASN1Sequence)new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();
			
			/* Loop over all policy OIDs */
		    for (int pos=0; pos<seq.size(); pos++) {
		        //PolicyInformation pol = new PolicyInformation((ASN1Sequence)seq.getObjectAt(pos));
		    	PolicyInformation pol =  PolicyInformation.getInstance(seq.getObjectAt(pos));
		        policy.add(pol.getPolicyIdentifier().getId());
		        log.debug("quatro Policy: {}", policy);
//		        System.out.println("Found policy: "+policy); // adapt as needed...
		    }
		} catch (Exception e) {
			// TODO Auto-generated catch block
			log.debug("quatro Exception: {}", e.getMessage());
		}
		
		return policy;
	}

	
	//Used to get the end user certificate
	private java.security.cert.X509Certificate getEndUserCertificate(java.security.cert.X509Certificate[] certChain) {
		ProxyUtils proxyUtils = new ProxyUtils();

		if (!proxyUtils.getEndUserCertificate(certChain).equals(null))
			return proxyUtils.getEndUserCertificate(certChain);
		return null;
	}

	private java.security.cert.X509Certificate[] AttributeToX509CertificateChain(Set<Attribute> attributes,
			String element) throws PIPProcessingException {
		java.security.cert.X509Certificate[] pemChain = null;
		NonValidatingCertPathBuilder bla = null;
		if (attributes.size() < 1) {
			throw new PIPProcessingException("Decision request " + element + " without any chain!");
		}

		// Contains all certificates as a string
		for (Attribute attribute : attributes) {
			Set<Object> attributeValues = attribute.getValues();

			// Used for other values
			for (Object attributeValue : attributeValues) {

				try {
					// cert = convertToPemObject(value);
					pemChain = convertToPemObject(attributeValue.toString());

					// Set nonCriticalExstenionOIDs =
					// cert.getBasicConstraints();
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					log.debug("quatro CertificateException: {}", e.getMessage());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					log.debug("quatro IOException: {}", e.getMessage());
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					log.debug("quatro KeyStoreException: {}", e.getMessage());
				}
			}
		}

		return pemChain;

	}

	/**
	 * Converts a PEM formatted String to a {@link X509Certificate} instance.
	 *
	 * @param pem
	 *            PEM formatted String
	 * @return a PemObject instance
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public java.security.cert.X509Certificate[] convertToPemObject(String pem)
			throws CertificateException, IOException, KeyStoreException {
		CertificateUtils ChainPem = new CertificateUtils();
		try {	
			InputStream pr = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
			return ChainPem.loadCertificateChain(pr, Encoding.PEM);
		} catch (IOException e) {
			log.debug("quatro IOException: {}", e.getMessage());
		}

		return null;
	}
}
