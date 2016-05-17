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

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.LazySet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Class to test the InInfoFileIssuerDNMatcher class. Each test has 3 variants.
 * Test one expects a success. Test two expects a failure and test three is made
 * entirely of non existing stuff. Test tree expects a fail.
 * 
 * Each tested method of the PIP InInfoFileIssuerDNMatcher, is chosen by a
 * purpose. The purpose is explained in each test. Each test uses a default
 * format for explaining. Explained is 1: What the test does. 2: Explanation of
 * why I expect a certain result. 3: Explanation of the expected test result. 4:
 * Explanation of the test.
 * 
 * @author Rens Visser
 * @version 1.0
 * @since 1.0
 */
public class InInfoFileIssuerDNMatcherTest {
	InInfoFileIssuerDNMatcher InInfoFileIssuerDNMatcherPIP = null;
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIPTest.class);
	String[] noAcceptedAttributes;
	String[] acceptedAttributes;
	Request globalRequest = new Request();
	Attribute correctIssuerDNInformation;
	Attribute incorrectIssuerDNInformation;

	/**
	 * Default String of trusted certificate directory: {@value}
	 */
	private final static String TRUSTED_CERTIFICATE_DIRECTORY = "/etc/grid-security/certificates/";

	/**
	 * The method contains a valid X509 certificate
	 *
	 * @return Returns a PEM encoded String containing a valid X509 certificate.
	 */
	private String getEndCertificateValid() {
		return "-----BEGIN CERTIFICATE-----\n" + "MIIDcjCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQsFADBDMQswCQYDVQQGEwJOTDEQ"
				+ "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMRQwEgYDVQQDDAtUZXN0IFN1"
				+ "YiBDQTAeFw0xNjA1MTMxMjM0MDlaFw0xNzA1MTMxMjM0MDlaMDsxCzAJBgNVBAYT"
				+ "Ak5MMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDANQRFAxDDAKBgNVBAMMA0Js"
				+ "YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO7ILEL4akFo1l81D6jm"
				+ "xTXPYMmEna5eyMowEdUVLZveBBpi5L8nd3hNj/y+ndZFK25NZR+xhQjx/h++s7x3"
				+ "4AxSCJIlyUrOwGbmwCS8DPX3qYRFzRajQtMF0in5irBxFcTWAyn4G0lpq+ef46qA"
				+ "k6iwGP4Mf9cRqyvf5XCbbjRQZGu55niOYf8STh3LNNv7yE4Nup+C1aZqUD2GdA+S"
				+ "yN/lYENXxdA5XxxDZM3cmEbQkPSbYOk+8zXrMld2lgISxsm+R8p23juevA1/aznK"
				+ "FWituyUnW3vA1AHmHDsx9/O3aM4WJ8D3ziS1RHLawOnEucvC1aCQAfSqxG/7pmHu"
				+ "CS8CAwEAAaN5MHcwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBLAwFwYDVR0g"
				+ "BBAwDjAMBgoqhkiG90wFAgIBMB8GA1UdIwQYMBaAFHOoXcbXArOvtKmxK3u2rm1Z"
				+ "ueijMB0GA1UdDgQWBBQmMWIFT9x130x3iMffRAodM756tTANBgkqhkiG9w0BAQsF"
				+ "AAOCAQEAHMkUf5bm7oi31yJinrArO+9zOco4lyxwQSkvHjWYnGvfKG3BQj4DIxUa"
				+ "fC1TJPrd6D1b7zMRp9/VyOvj5wI1OuAFNyaw3VieFa0Jd005vkUT5y5nwCvkGkrj"
				+ "smx98JHAsVphEhr2uNhPaRWDlXCTr/wk1CqWPKhWTph3FvPPsm39pwLBUUuy7MlJ"
				+ "K9dztRQQNLC6eR5OMPUOsUBpgPFg0KFAFuSF2EZox4N9Jgn7N2gJ3qGRZnBL7S7E"
				+ "/N0/5b6fOiwJto9k45hO3wpDPv9Cq2yGxWtO/GGK1toa7FS7sb2zNjqGsfHH9Mto"
				+ "bQZwEc1+eUp0QKn4UCCSd7tU5xQ8WQ==" + "\n-----END CERTIFICATE-----";
	}

	/**
	 * The method contains a invalid X509 certificate
	 *
	 * @return Returns a PEM encoded String containing a invalid X509
	 *         certificate.
	 */
	private String getEndCertificateInvalid() {
		return "-----BEGIN CERTIFICATE-----\n" + "MIIDcjCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQsFADBDMQswCQYDVQQGEwJOTDEQ"
				+ "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMRQwEgYDVQQDDAtUZXN0IFN1"
				+ "YiBDQTAeFw0xNjA1MTMxMjM0MDlaFw0xNzA1MTMxMjM0MDlaMDsxCzAJBgNVBAYT"
				+ "Ak5MMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDANQRFAxDDAKBgNVBAMMA0Js"
				+ "YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO7ILEL4akFo1l81D6jm"
				+ "xTXPYMmEna5eyMowEdUVLZveBBpi5L8nd3hNj/y+ndZFK25NZR+xhQjx/h++s7x3"
				+ "4AxSCJIlyUrOwGbmwCS8DPX3qYRFzRajQtMF0in5irBxFcTWAyn4G0lpq+ef46qA"
				+ "k6iwGP4Mf9cRqyvf5XCbbjRQZGu55niOYf8STh3LNNv7yE4Nup+C1aZqUD2GdA+S"
				+ "yN/lYENXxdA5XxxDZM3cmEbQkPSbYOk+8zXrMld2lgISxsm+R8p23juevA1/aznK"
				+ "FWituyUnW3vA1AHmHDsx9/O3aM4WJ8D3ziS1RHLawOnEucvC1aCQAfSqxG/7pmHu"
				+ "CS8CAwEAAaN5MHcwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBLAwFwYDVR0g"
				+ "BBAwDjAMBgoqhkiG90wFAgIBMB8GA1UdIwQYMBaAFHOoXcbXArOvtKmxK3u2rm1Z"
				+ "ueijMB0GA1UdDgQWBBQmMWIFT9x130x3iMffRAodM756tTANBgkqhkiG9w0BAQsF"
				+ "AAOCAQEAHMkUf5bm7oi31yJinrArO+9zOco4lyxwQSkvHjWYnGvfKG3BQj4DIxUa"
				+ "fC1TJPrd6D1b7zMRp9/VyOvj5wI1OuAFNyaw3VieFa0Jd005vkUT5y5nwCvkGkrj"
				+ "smx98JHAsVphEhr2uNhPaRWDlXCTr/wk1CqWPKhWTph3FvPPsm39pwLBUUuy7MlJ"
				+ "K9dztRQQNLC6eR5OMPUOsUBpgPFg0KFAFuSF2EZox4N9Jgn7N2gJ3qGRZnBL7S7E"
				+ "/N0/5b6fOiwJto9k45hO3wpDPv9Cq2yGxWtO/GGK1toa7FS7sb2zNjqGsfHH9Mto"
				+ "bQZwEc1+eUp0QKn4UCCSd7tU5xQ8WQ==" + "\n-----END CERTIFICATE-----";
	}

	/**
	 * The method contains a bogus X509 certificate
	 *
	 * @return Returns a PEM encoded String containing a bogus X509 certificate.
	 */
	private String getEndCertificateBogus() {
		return "-----BEGIN BOGUS-----\n" + "BogusMIIDcjCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQsFADBDMQswCQYDVQQGEwJOTDEQ"
				+ "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UBogusECwwDUERQMRQwEgYDVQQDDAtUZXN0IFN1"
				+ "YiBDQTAeFw0xNjA1MTMxMjM0MDlaFw0xNzA1BogusMTMxMjM0MDlaMDsxCzAJBgNVBAYT"
				+ "Ak5MMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDBogusANQRFAxDDAKBgNVBAMMA0Js"
				+ "YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOBogus7ILEL4akFo1l81D6jm"
				+ "xTXPYMmEna5eyMowEdUVLZveBBpi5L8nd3hNj/y+ndZFK25NZR+BogusxhQjx/h++s7x3"
				+ "4AxSCJIlyUrOwGbmwCS8DPX3qYRFzRajQtMF0in5irBxFcTWAyn4G0lpBogusBogusq+ef46qA"
				+ "k6iwBogusGP4Mf9cRqyvf5XCbbjRQZGu55niOYf8STh3LNNv7yE4Nup+C1aZqUD2GdA+S"
				+ "yN/lYENXxBogusdA5XxxDZM3cmEbQkPSbYOk+8zXrMld2lgISxsm+R8p23juevA1/aznK"
				+ "FWituyUnW3vA1ABogusHmHDsx9/O3aM4WJ8D3ziS1RHLawOnEucvC1aCQAfSqxG/7pmHu"
				+ "CS8CAwEAAaN5MHcwDAYBogusDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBLAwFwYDVR0g"
				+ "BBAwDjAMBgoqhkiG90wFAgIBvMB8GA1UdIwQYMBaAFHOoXcbXArOvtKmxK3u2rm1Z"
				+ "ueijMB0GA1UdDgQWBBQmMWIFT9x130x3iMffRAodM756tTANBgkqhkiG9w0BAQsF"
				+ "AAOCAQEAHMkUf5bm7oi31yJinBogusrArO+9zOco4lyxwQSkvHjWYnGvfKG3BQj4DIxUa"
				+ "fC1TJPrd6D1b7zMRp9/VyOvj5wI1OuBogusBogusvAFNyaw3VieFa0Jd005vkUT5y5nwCvkGkrj"
				+ "smx98JHAsVphEhr2uNhPaRWDlXCTr/wk1CqWPKhWTBogusBogusBogusph3FvPPsm39pwLBUUuy7MlJ"
				+ "K9dztRQQNLC6eR5OMPUOsUBpgPFg0KFAFuSF2EZox4N9Jgn7N2gJ3qGRBogusZnBL7S7E"
				+ "/N0/5b6fOiwJto9k45hO3wpDPv9Cq2yGxWtO/GGK1toa7FS7sb2zNjqGsfHH9BogusMto"
				+ "bQZwEc1+eUp0QKn4UCCSd7tU5xQ8WQ==" + "\n-----END BOGUS-----";
	}

	/**
	 * Creates a Attribute object, the attribute object is filled with a correct
	 * subject-x509-issuer ID and data.
	 * 
	 * @return Correct filled in attribute object.
	 */
	private Attribute getCorrectSubjectX509Issuer() {
		Attribute correctX509 = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
		correctX509.setDataType(Attribute.DT_STRING);
		correctX509.getValues().add("/C=NL/O=Example/OU=PDP/CN=rootCA");
		return correctX509;
	}

	/**
	 * Creates a Attribute object, the attribute object is filled with a
	 * incorrect subject-x509-issuer ID and data.
	 * 
	 * @return Correct filled in attribute object.
	 */
	private Attribute getIncorrectSubjectX509Issuer() {
		Attribute incorrectX509 = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
		incorrectX509.setDataType(Attribute.DT_STRING);
		incorrectX509.getValues().add("/C=NL/O=Example/OU=PDP/CN=ACtoor");
		return incorrectX509;
	}

	/**
	 * Creates a Attribute object, the attribute object is filled with a Bogus
	 * subject-x509-issuer ID and data.
	 * 
	 * @return Correct filled in attribute object.
	 */
	private Attribute getBogusSubjectX509Issuer() {
		Attribute incorrectX509 = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
		incorrectX509.setDataType(Attribute.DT_STRING);
		incorrectX509.getValues().add("Bogus");
		return incorrectX509;
	}

	/**
	 * Used to set up resources used in the test. The resources consists of a
	 * global request object, Correct issuer DN, Incorrect issuer DN, Correct
	 * PolicyOIDs, incorrect policyOIDs.
	 */
	@Before
	public void initialize() {
		Subject sub = new Subject();
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		Attribute pemString = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info");
		pemString.setDataType(Attribute.DT_STRING);
		Attribute policyOID = new Attribute("http://authz-interop.org/xacml/subject/ca-policy-oid");
		policyOID.setDataType(Attribute.DT_STRING);

		Set<Subject> subjects = globalRequest.getSubjects();

		try {
			policyOID.getValues().add("1.2.840.113612.5.2.2.1");
			policyOID.getValues().add("2.16.840.1.114412.4.31.1");
			policyOID.getValues().add("1.2.840.113612.5.2.3.3.3");

			correctIssuerDNInformation = getCorrectSubjectX509Issuer();

			incorrectIssuerDNInformation = getIncorrectSubjectX509Issuer();

			pemString.getValues().add(getEndCertificateValid());

			subjectAttributes.add(correctIssuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			globalRequest.getSubjects().addAll(subjects);
		} catch (Exception e) {

		}
	}

	/**
	 * This test is used to find out if all the code runs as designed. The test
	 * is designed a black-box test. When data is filled in correctly and the
	 * expected output is matched with the output. The test has succeeded.
	 * 
	 * In this test a "true" is expected. When a true is returned from the
	 * method populateRequest(), \ the PIP applied to the incoming request. This
	 * PIP assumes a true to be returned. I made the test to figure out if the
	 * PIP will, run, break or malfunction when the method populateRequest() is
	 * called.
	 * 
	 */
	@Test
	public void testPopulateRequestSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Boolean b;
		try {
			assertEquals(true, InInfoFileIssuerDNMatcherPIP.populateRequest(globalRequest));
		} catch (Exception e) {
			fail(e.getMessage());
		}

	}

	/**
	 * This test is used to find out if all the code runs as designed. The test
	 * is designed a black-box test. When data is filled in incorrectly and the
	 * expected output is matched with the output. The test has succeeded.
	 * 
	 * In this test a "false" is expected. When a false is returned from the
	 * method populateRequest(), \ the PIP applied to the incoming request. This
	 * PIP assumes a false to be returned. I made the test to figure out if the
	 * PIP will, run, break or malfunction when the method populateRequest() is
	 * called.
	 * 
	 */
	@Test
	public void testPopulateRequestFailure() {
		globalRequest = new Request();
		Subject sub = new Subject();
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		Attribute pemString = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info");
		pemString.setDataType(Attribute.DT_STRING);
		Attribute policyOID = new Attribute("http://authz-interop.org/xacml/subject/ca-policy-oid");
		policyOID.setDataType(Attribute.DT_STRING);

		Set<Subject> subjects = globalRequest.getSubjects();

		try {
			policyOID.getValues().add("1.2.840.113612.5.2.2.1");
			policyOID.getValues().add("2.16.840.1.114412.4.31.1");
			policyOID.getValues().add("1.2.840.113612.5.2.3.3.3");

			incorrectIssuerDNInformation = getBogusSubjectX509Issuer();

			pemString.getValues().add(getEndCertificateInvalid());

			subjectAttributes.add(incorrectIssuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			globalRequest.getSubjects().addAll(subjects);
		} catch (Exception e) {

		}

		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Boolean b;
		try {
			assertEquals(false, InInfoFileIssuerDNMatcherPIP.populateRequest(globalRequest));
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	/**
	 * This test is used to find out if all the code runs as designed. The test
	 * is designed a black-box test. When data is filled in incorrectly and the
	 * expected output is matched with the output. The test has succeeded.
	 * 
	 * In this test a "false" is expected. When a false is returned from the
	 * method populateRequest(), \ the PIP applied to the incoming request. This
	 * PIP assumes a false to be returned. I made the test to figure out if the
	 * PIP will, run, break or malfunction when the method populateRequest() is
	 * called.
	 * 
	 */
	@Test
	public void testPopulateRequestBogus() {
		globalRequest = new Request();
		Subject sub = new Subject();
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		Attribute pemString = new Attribute("Bogus");
		pemString.setDataType(Attribute.DT_STRING);
		Attribute policyOID = new Attribute("Bogus");
		policyOID.setDataType(Attribute.DT_STRING);

		Set<Subject> subjects = globalRequest.getSubjects();

		try {
			policyOID.getValues().add("Bogus1");
			policyOID.getValues().add("Bogus2");
			policyOID.getValues().add("Bogus3");

			Attribute bogusIssuerDNInformation = getBogusSubjectX509Issuer();

			pemString.getValues().add(getEndCertificateBogus());

			subjectAttributes.add(bogusIssuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			globalRequest.getSubjects().addAll(subjects);
		} catch (Exception e) {
			log.debug(e.getMessage());
		}

		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Boolean b;
		try {
			assertEquals(false, InInfoFileIssuerDNMatcherPIP.populateRequest(globalRequest));
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	/**
	 * The method getIssuerDNFromSubject() extracts the IssuerDN from an
	 * incoming subject. This test is designed to see if the expected issuerDN
	 * is extracted. All information in this test is correct. The test is
	 * designed as a black-box test. I want to know if the method functions
	 * properly.
	 * 
	 * The correct issuer DN consists of
	 * "/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3"
	 * The result that must come back is
	 * "/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3"
	 * , if the expected and actual result match, the test is a success. It is
	 * expected that the method will succeed.
	 */
	@Test
	public void testGetIssuerDNFromSubjectSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Attribute issuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
		issuerDNInformation.setDataType(Attribute.DT_STRING);
		issuerDNInformation.getValues()
				.add("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3");
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		subjectAttributes.add(issuerDNInformation);

		assertEquals("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3",
				InInfoFileIssuerDNMatcherPIP.getIssuerDNFromSubject(subjectAttributes));
	}

	/**
	 * The method getIssuerDNFromSubject() extracts the IssuerDN from an
	 * incoming subject. This test is designed to see if the fail safe works in
	 * the method. All information in this test is incorrect. The test is
	 * designed as a black-box test. I want to know if the method functions
	 * properly, with incorrect data.
	 * 
	 * I expect a null as return. A null is returned when no issuer DN matches
	 * the input. It is expected that the method will fail.
	 */
	@Test
	public void testGetIssuerDNFromSubjectFailure() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Attribute issuerDNInformation = new Attribute("ttp://authz-interop.org/xacml/subject/ca-policy-oid");
		issuerDNInformation.setDataType(Attribute.DT_STRING);
		issuerDNInformation.getValues()
				.add("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3");
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		subjectAttributes.add(issuerDNInformation);
		try {
			assertEquals(null, InInfoFileIssuerDNMatcherPIP.getIssuerDNFromSubject(subjectAttributes));
		} catch (Exception e) {
			return;
		}
	}

	/**
	 * The method getIssuerDNFromSubject() extracts the IssuerDN from an
	 * incoming subject. This test is designed to see if the fail safe works in
	 * the method. All information in this test is bogus. The test is designed
	 * as a black-box test. I want to know if the method functions properly,
	 * with bogus data.
	 * 
	 * I expect a null as return. A null is returned when no issuer DN matches
	 * the input. It is expected that the method will fail.
	 */
	@Test
	public void testGetIssuerDNFromSubjectBogus() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		Attribute issuerDNInformation = new Attribute("Bogus");
		issuerDNInformation.setDataType(Attribute.DT_STRING);
		issuerDNInformation.getValues().add("Bogus");
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		subjectAttributes.add(issuerDNInformation);
		try {
			assertEquals(null, InInfoFileIssuerDNMatcherPIP.getIssuerDNFromSubject(subjectAttributes));
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	/**
	 * The method issuerDNParser, checks if the given *.info file contains the
	 * Issuer DN. With a match is found, a true is returned. The code then knows
	 * the correct info file is found. THe info file is send to the Argus
	 * framework. This test is a black-box test. All the data inserted is
	 * correct.
	 * 
	 * I expect a true as result. When the data in the input and the data in the
	 * info file match, there is a match. Therefore I expect a true returned. It
	 * is expected that the method will succeed.
	 */
	@Test
	public void testIssuerDNParserSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		InInfoFileIssuerDNMatcherPIP.CertificateIssuerDN = "/C=NL/O=Example/OU=PDP/CN=rootCA";
		try {
			assertEquals(true, InInfoFileIssuerDNMatcherPIP.issuerDNParser("rootCA.info"));
		} catch (Exception e) {
			e.getMessage();
		}
	}

	/**
	 * The method issuerDNParser, checks if the given *.info file contains the
	 * Issuer DN. With no matches are found, a false is returned. The code then
	 * knows that no correct info file is found. The info file is send to the
	 * Argus framework. This test is a black-box test. All the data inserted is
	 * incorrect.
	 * 
	 * I expect a false as result. When the data in the input and the data in
	 * the info file mismatch, there is no match. Therefore I expect a false
	 * returned. It is expected that the method will fail.
	 */
	@Test
	public void testIssuerDNParserFailure() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		InInfoFileIssuerDNMatcherPIP.CertificateIssuerDN = "/C=NL/O=Example/OU=PDP/CN=rootCA";
		try {
			assertEquals(false, InInfoFileIssuerDNMatcherPIP.issuerDNParser("AAACertificateServices.info"));
		} catch (Exception e) {
			e.getMessage();
		}
	}

	/**
	 * The method issuerDNParser, checks if the given *.info file contains the
	 * Issuer DN. With no matches are found, a false is returned. The code then
	 * knows that no correct info file is found. The info file is send to the
	 * Argus framework. This test is a black-box test. All the data inserted is
	 * bogus.
	 * 
	 * I expect a false as result. When the data in the input and the data in
	 * the info file mismatch, there is no match. Therefore I expect a false
	 * returned. It is expected that the method will fail.
	 */
	@Test
	public void testIssuerDNParserBogus() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd", TRUSTED_CERTIFICATE_DIRECTORY);
		InInfoFileIssuerDNMatcherPIP.CertificateIssuerDN = "BogusIssuerOfCertificate";
		try {
			assertEquals(false, InInfoFileIssuerDNMatcherPIP.issuerDNParser("BogusApplePie"));
		} catch (Exception e) {
			e.getMessage();
		}
	}
}
