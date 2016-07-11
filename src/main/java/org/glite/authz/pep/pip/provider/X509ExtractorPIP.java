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

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyUtils;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;

import org.bouncycastle.asn1.x509.X509Extension;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.List;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * This PIP can extract several different attributes from a X.509v3 certificate,
 * as obtained from the {@link ATTR_KEY_INFO} attribute, and stores them as
 * subject attributes. Which attributes are being set is determined by the
 * {@link #acceptedAttrIDs}.
 * @author Mischa Sall&eacute;, Rens Visser
 */
public class X509ExtractorPIP extends AbstractPolicyInformationPoint {
    /** Class logger instance. */
    private final Logger log = LoggerFactory.getLogger(X509ExtractorPIP.class);

    /** Default name of key-info attribute(s) ({@value}) */
    private final static String ATTR_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info";

    /** Default name of issuer DN attribute ({@value}) */
    protected final static String ATTR_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** Default name of CA policy OIDs attribute ({@value}) */
    protected final static String ATTR_CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

    /** enum describing the different supported attributes to be set */
    protected enum AcceptedAttr {
	/** corresponds to {@link #ATTR_X509_ISSUER} */
	ACCEPT_ATTR_X509_ISSUER,
	/** corresponds to {@link #ATTR_CA_POLICY_OID} */
	ACCEPT_ATTR_CA_POLICY_OID,
    }

    /** Array of accepted attribute ID(s) in incoming request that will be
     * populated. Default none */
    private static AcceptedAttr[] acceptedAttrIDs = null;


    /**
     * Sets list of accepted attributes, default is empty
     * @param acceptedAttrIDs list of accepted attributes
     * @see AcceptedAttr
     */
    protected void setAcceptedAttrIDs(AcceptedAttr[] acceptedAttrIDs) {
	this.acceptedAttrIDs = acceptedAttrIDs;
    }

    /**
     * Constructs a X509ExtractorPIP instance, using both PIP ID and list of
     * accepted attributes
     * @param pipid ID of this PIP.
     * @param acceptedAttrIDs array of accepted attributes
     */
    public X509ExtractorPIP(String pipid, AcceptedAttr[] acceptedAttrIDs) {
	super(pipid);

	// Set list of accepted attributes
	if (acceptedAttrIDs.length > 0)
	    this.acceptedAttrIDs = acceptedAttrIDs;
    }

    /**
     * Constructs a X509ExtractorPIP instance, using only PIP ID, list of
     * accepted attributes needs to be set using
     * {@link #setAcceptedAttrIDs(AcceptedAttr[])}
     * @param pipid ID of this PIP.
     * @see #X509ExtractorPIP(String, AcceptedAttr[])
     * @see #setAcceptedAttrIDs(AcceptedAttr[])
     */
    public X509ExtractorPIP(String pipid) {
	this(pipid, null);
    }

    /**
     * {@inheritDoc}
     * This PIP adds {@value #ATTR_X509_ISSUER} and/or
     * {@value #ATTR_CA_POLICY_OID} attributes to the corresponding subjects.
     * @param request the incoming request.
     * @throws PIPProcessingException in case of errors.
     * @return boolean: true when attribute has been populated, false otherwise.
     */
    public boolean populateRequest(Request request) throws PIPProcessingException {
	long t0=System.nanoTime();
	boolean pipprocessed=false;

	// Get all subjects from the request, should be at least one, warn when
	// there are more than 1
	Set<Subject> subjects = request.getSubjects();
	if (subjects.isEmpty())	{
	    log.error("Request has no subjects");
	    throw new PIPProcessingException("No subject found in request!!");
	}
	if (subjects.size()>1)
	    log.warn("Request has "+subjects.size()+" subjects, taking first match");
	
	// Loop over all subjects to look for end-entity certificate
	for (Subject subject : subjects) {
	    Set<Attribute> attributes = subject.getAttributes();
	    X509Certificate cert = getCertFromSubject(attributes);
	    if (cert == null)
		continue;

	    // Now see what we should handle
	    for (int i=0; i < acceptedAttrIDs.length; i++) {
		switch (acceptedAttrIDs[i])	{
		    case ACCEPT_ATTR_CA_POLICY_OID:
			String[] oids = getCAPolicyOids(cert);
			if (oids==null)	{ // no OIDs or error
			    log.debug("Certificate does not contain any OIDs");
			    break;
			}
			Attribute attrCAPolicyOids = new Attribute(ATTR_CA_POLICY_OID);
			Set<Object> values = attrCAPolicyOids.getValues();
			for (int j=0; j<oids.length; j++)
			    values.add(oids[j]);
			attributes.add(attrCAPolicyOids);
			pipprocessed=true;
			// Log that we succeeded
			log.debug("Added attribute \""+ATTR_CA_POLICY_OID+"\"");
			break;
		    case ACCEPT_ATTR_X509_ISSUER:
			String str = cert.getIssuerX500Principal().getName();
			if (str==null)	{ // no OIDs or error
			    log.warn("Certificate does not contain a valid Issuer");
			    break;
			}
			String value = OpensslNameUtils.convertFromRfc2253(str, false);
			Attribute attrIssuerDN = new Attribute(ATTR_X509_ISSUER);
			attrIssuerDN.getValues().add(value);
			attributes.add(attrIssuerDN);
			pipprocessed=true;
			// Log that we succeeded
			log.debug("Added attribute \""+ATTR_X509_ISSUER+"\"");
			break;
		    default:
			throw new PIPProcessingException("Unknown attribute "+acceptedAttrIDs[i]+" specified");
		}
	    }
	}

	// Log statistics
	log.debug("PIP parsing took "+(System.nanoTime()-t0)/1000000.0+" msec");

	return pipprocessed;
    }

    /**
     * Retrieves the end-entity certificate from a set of (subject)attributes.
     * @param attributes (subject) attributes to parse for EEC
     * @return end-entity certificate
     */
    private X509Certificate getCertFromSubject(Set<Attribute> attributes)	{
	// Loop over all attributes, looking for ATTR_X509_ISSUER
	for (Attribute attr: attributes) {
	    if (ATTR_KEY_INFO.equals(attr.getId()))	{
		Set<Object> attributeValues = attr.getValues();
		for (Object value: attributeValues)    {
		    InputStream pemReader = new ByteArrayInputStream(((String)value).getBytes(StandardCharsets.UTF_8));
		    try {
			// Do we need to close pemReader?
			X509Certificate[] chain = CertificateUtils.loadCertificateChain(pemReader, Encoding.PEM);
			X509Certificate cert = ProxyUtils.getEndUserCertificate(chain);
			return cert;
		    } catch (IOException e) {
			log.error("Parsing value as a certificate failed: "+e.getMessage());
		    }
		}
	    }
	}
	// No cert found
	return null;
    }

    /**
     * Tries to obtain policy OIDs from end-entity certificate
     * @param cert input (end-entity) certificate
     * @return String array of policy OIDs
     */
    private String[] getCAPolicyOids(X509Certificate cert)  {
	List<String> oidList = new LazyList<String>();

	String certPolicies = X509Extension.certificatePolicies.toString();
	byte[] extvalue = cert.getExtensionValue(certPolicies);
	if (extvalue==null)
	    return null;
	
	ASN1Sequence seq;
	try {
	    DEROctetString oct=(DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
	    seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();
	} catch (IOException e)	{
	    log.error("Trying to obtain policyinfo from certificate failed: "+e.getMessage());
	    return null;
	}

	for (int pos = 0; pos < seq.size(); pos++) {
	    PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(pos));
	    String id = policyInfo.getPolicyIdentifier().getId();
	    oidList.add(id);
	}

	// Return oidList
	return oidList.toArray(new String[0]);
    }
}