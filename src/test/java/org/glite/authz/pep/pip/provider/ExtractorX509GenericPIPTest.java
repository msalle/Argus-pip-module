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

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.util.Set;

import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.LazySet;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP;

import org.junit.Before;
import org.junit.Test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Class to test the ExtractorX509GenericPIP class. Each test has 3 variants.
 * Test one expects a success. Test two expects a failure and test three is made
 * entirely of non existing stuff. Test tree expects a fail.
 * 
 * Each tested method of the PIP ExtractorX509GenericPIP, is chosen by a
 * purpose. The purpose is explained in each test. Each test uses a default
 * format for explaining. Explained is 1: What the test does. 2: Explanation of
 * why I expect a certain result. 3: Explanation of the expected test result. 4:
 * Explanation of the test.
 * 
 * @author Rens Visser
 * @version 1.0
 * @since 1.0
 */
public class ExtractorX509GenericPIPTest {
	ExtractorX509GenericPIP extractorPIP = null;
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIPTest.class);
	String[] noAcceptedAttributes;
	String[] acceptedAttributes;
	String[] noAcceptedAttributesBogus;
	String acceptedUserCertificate, notAcceptedUserCertificate, notAcceptedUserCertificateBogus;
	Request globalRequest = new Request();

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
		return "-----BEGIN CERTIFICATE-----\n"
				+ "\nTHis definetly is a fake certificate!\nMIIDcjCCAlqgAwIBAgIBADANBgkqhkiG9w0BAQsFADBDMQswCQYDVQQGEwJOTDEQ"
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
	 * Transforms a encoded PEM string into a {@link X509Certificate} and
	 * returns the X509Certificate object.
	 * 
	 * @param str
	 *            The PEM string representation of the X509 certificate from.
	 * @return Returns a X509Certificate object.
	 * 
	 * @throws Exception
	 */
	private X509Certificate getCertificateObject(String str) {
		InputStream inStream = null;
		X509Certificate cert = null;
		try {
			inStream = new ByteArrayInputStream(str.getBytes());
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) cf.generateCertificate(inStream);
		} catch (Exception e) {
			log.debug(e.getMessage());
		} finally {
			try {
				if (inStream != null) {
					inStream.close();
				}
			} catch (Exception e2) {
				log.debug(e2.getMessage());
			}
		}
		return cert;
	}

	/**
	 * Used to set up resources used in the test. The resources consists of a
	 * global request object, accepted attributes, not accepted attributes,
	 * accepted user certificates, not accepted user certificates, bogus user
	 * certificates, PolicyOIDs and incorrect policyOIDs.
	 */
	@Before
	public void initialize() {
		noAcceptedAttributes = new String[5];
		acceptedAttributes = new String[2];
		noAcceptedAttributesBogus = new String[3];
		Subject sub = new Subject();
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		Attribute pemString = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info");
		pemString.setDataType(Attribute.DT_STRING);
		Attribute policyOID = new Attribute("http://authz-interop.org/xacml/subject/ca-policy-oid");
		policyOID.setDataType(Attribute.DT_STRING);

		noAcceptedAttributes[0] = "http://glite.org/xacml/profile/grid-ce/1 .0";
		noAcceptedAttributes[1] = "http://glite.org/xacml/profile/grid-wn/1 .0";
		noAcceptedAttributes[2] = "http://          glite.org/xacml/profile/grid-wn/1.0";
		noAcceptedAttributes[3] = "http://glite.org/ sdfxsdv acml/profilesdf/grid-wn/1.0";
		noAcceptedAttributes[4] = "ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=";

		noAcceptedAttributesBogus[0] = "Bogus0";
		noAcceptedAttributesBogus[1] = "Bogus1";
		noAcceptedAttributesBogus[2] = "Bogus2";

		acceptedAttributes[0] = "http://authz-interop.org/xacml/subject/ca-policy-oid";
		acceptedAttributes[1] = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

		Set<Subject> subjects = globalRequest.getSubjects();

		try {
			acceptedUserCertificate = getEndCertificateValid();
			notAcceptedUserCertificate = getEndCertificateInvalid();
			notAcceptedUserCertificateBogus = getEndCertificateBogus();

			policyOID.getValues().add("1.2.840.113612.5.2.2.1");
			policyOID.getValues().add("2.16.840.1.114412.4.31.1");
			policyOID.getValues().add("1.2.840.113612.5.2.3.3.3");

			Attribute issuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
			issuerDNInformation.setDataType(Attribute.DT_STRING);
			issuerDNInformation.getValues()
					.add("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3");

			pemString.getValues().add(acceptedUserCertificate);

			subjectAttributes.add(issuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			globalRequest.getSubjects().addAll(subjects);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			e.getMessage();
		}
	}

	/**
	 * The test is used to see if the PIP instantiates correctly or not.
	 * 
	 * The expected result is
	 * "Policy Information Point ID may not be null or empty". The result is
	 * expected, because the data inserted is incorrect. The constructor method
	 * has a build in fail safe. We want to see if the fail safe works.
	 */
	@Test
	public void testOneExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(null, null);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("Policy Information Point ID may not be null or empty", e.getMessage());
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * The test is used to see if the PIP instantiates correctly or not.
	 * 
	 * The expected result is
	 * "Policy Information Point ID may not be null or empty". The result is
	 * expected, because the data inserted is incorrect. The constructor method
	 * has a build in fail safe. We want to see if the fail safe works.
	 */
	@Test
	public void testTwoExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP("", null);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("Policy Information Point ID may not be null or empty", e.getMessage());
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * The test is used to see if the PIP instantiates correctly or not.
	 * 
	 * The expected result is
	 * "Policy Information Point ID may not be null or empty". The result is
	 * expected, because the data inserted is incorrect. The constructor method
	 * has a build in fail safe. We want to see if the fail safe works.
	 */
	@Test
	public void testTreeExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(null, new String[20]);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("Policy Information Point ID may not be null or empty", e.getMessage());
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * The test is used to see if the PIP instantiates correctly or not.
	 * 
	 * The expected result is
	 * "Policy Information Point ID may not be null or empty". The result is
	 * expected, because the data inserted is incorrect. The constructor method
	 * has a build in fail safe. We want to see if the fail safe works.
	 */
	@Test
	public void testFourExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP("", acceptedAttributes);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("Policy Information Point ID may not be null or empty", e.getMessage());
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * The test is used to see if the PIP instantiates correctly or not.
	 * 
	 * The expected result is a working PIP object. The result is expected,
	 * because the data inserted is correct. The constructor method has a build
	 * in fail safe. We want to see if the fail safe works does not stop the PIP
	 * from executing.
	 */
	@Test
	public void testFiveExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(
					"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
					acceptedAttributes);
			assertEquals(
					"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
					extractorPIP.getId());
		} catch (Exception e) {
			 log.debug(e.getMessage());
			fail(e.getMessage());
		}
		return;
	}

	/**
	 * This test is designed as a black-box test. populateRequest() is the main
	 * method of all PIPs. Therefore if the the expected result is returned, the
	 * entire PIP functions properly.
	 * 
	 * THe expected result is true. With a true the PIP applied to the request.
	 * With a true, the PIP functions properly.
	 */
	@Test
	public void testAcceptedIDsPopulateRequest() {
		try {
			extractorPIP = new ExtractorX509GenericPIP(
					"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
					acceptedAttributes);
			assertEquals(true, extractorPIP.populateRequest(globalRequest));
		} catch (Exception e) {
			 log.debug(e.getMessage());
			fail("Expected a succes! Somehow a error got thrown");
		}
		return;
	}

	/**
	 * This test is designed as a black-box test. populateRequest() is the main
	 * method of all PIPs. Therefore if the the expected result is returned, the
	 * entire PIP functions properly.
	 * 
	 * THe expected result is Non-handled attribute specified in ini file:
	 * http://glite.org/xacml/profile/grid-ce/1 .0. With a Non-handled attribute
	 * specified in ini file: http://glite.org/xacml/profile/grid-ce/1 .0 the
	 * PIP did not apply to the request. With a Non-handled attribute specified
	 * in ini file: http://glite.org/xacml/profile/grid-ce/1 .0, the PIP
	 * functions properly.
	 */
	@Test
	public void testNoAcceptedIDsPopulateRequest() {
		try {
			Set<Attribute> subjectAttributes = new LazySet<Attribute>();
			Attribute pemString = new Attribute("BogusKey-info");
			pemString.setDataType(Attribute.DT_STRING);
			Attribute policyOID = new Attribute("BogusOid");
			policyOID.setDataType(Attribute.DT_STRING);
			Subject sub = new Subject();
			Request localRequest = new Request();
			Set<Subject> subjects = localRequest.getSubjects();

			extractorPIP = new ExtractorX509GenericPIP("BogusPIPID", noAcceptedAttributes);

			policyOID.getValues().add("Bogus1OID");
			policyOID.getValues().add("Bogus2OID");
			policyOID.getValues().add("Bogus3OID");

			Attribute issuerDNInformation = new Attribute("BogusBogusAttribute");
			issuerDNInformation.setDataType(Attribute.DT_STRING);
			issuerDNInformation.getValues().add("BogusBOGUSBOGUSBOGUSsajksajksad");

			pemString.getValues().add(notAcceptedUserCertificate);

			subjectAttributes.add(issuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			localRequest.getSubjects().addAll(subjects);

			extractorPIP.populateRequest(localRequest);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("No pem String content in request! PIP ExtractorX509GenericPIP quited running...",
					e.getMessage());
			return;
		}
		fail("Expected a fail! Somehow a success is returned");
	}

	/**
	 * This test is designed as a black-box test. populateRequest() is the main
	 * method of all PIPs. Therefore if the the expected result is returned, the
	 * entire PIP functions properly.
	 * 
	 * The expected result is No pem String content in request! PIP
	 * ExtractorX509GenericPIP quited running.... With a No pem String content
	 * in request! PIP ExtractorX509GenericPIP quited running... the PIP did not
	 * apply to the request. With a No pem String content in request! PIP
	 * ExtractorX509GenericPIP quited running..., the PIP functions properly.
	 */
	@Test
	public void testNoAcceptedIDsPopulateRequestBogus() {
		try {
			Set<Attribute> subjectAttributes = new LazySet<Attribute>();
			Attribute pemString = new Attribute("BogusKey-info");
			pemString.setDataType(Attribute.DT_STRING);
			Attribute policyOID = new Attribute("BogusOid");
			policyOID.setDataType(Attribute.DT_STRING);
			Subject sub = new Subject();
			Request localRequest = new Request();
			Set<Subject> subjects = localRequest.getSubjects();

			extractorPIP = new ExtractorX509GenericPIP("BogusPIPID", noAcceptedAttributesBogus);

			policyOID.getValues().add("Bogus1OID");
			policyOID.getValues().add("Bogus2OID");
			policyOID.getValues().add("Bogus3OID");

			Attribute issuerDNInformation = new Attribute("BogusBogusAttribute");
			issuerDNInformation.setDataType(Attribute.DT_STRING);
			issuerDNInformation.getValues().add("BogusBOGUSBOGUSBOGUSsajksajksad");

			pemString.getValues().add(acceptedUserCertificate);

			subjectAttributes.add(issuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			localRequest.getSubjects().addAll(subjects);

			extractorPIP.populateRequest(localRequest);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("No pem String content in request! PIP ExtractorX509GenericPIP quited running...",
					e.getMessage());
			return;
		}
		fail("Expected a fail! Somehow a success is returned");
	}

	/**
	 * This test tests if the correct Policy OIDs are returned.
	 * 
	 * The expected result is [1.2.840.113612.5.2.2.1] With a
	 * [1.2.840.113612.5.2.2.1] the correct policy OID is extracted by the
	 * method getPolicyOIDs(). Get policy OIDs when extracted successful.
	 */
	@Test
	public void testGetPolicyOIDsSuccess() {
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		X509Certificate cert = getCertificateObject(getEndCertificateValid());

		try {
			assertEquals("[1.2.840.113612.5.2.2.1]", extractorPIP.getPolicyOIDs(cert).toString());
		} catch (Exception e) {
			log.error(e.getMessage());
			fail(e.getMessage());
		}
		return;
	}

	/**
	 * This test tests if the correct Policy OIDs are returned.
	 * 
	 * The expected result is null With a null the no policy OID is extracted by
	 * the method getPolicyOIDs(). Get policy OIDs when extracted successful,
	 * null if unseccesfull.
	 */
	@Test
	public void testGetPolicyOIDsFailure() {
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		X509Certificate cert = getCertificateObject(getEndCertificateInvalid());

		try {
			extractorPIP.getPolicyOIDs(cert);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals(null, e.getMessage());
			return;
		}
		fail("Test failed!");
	}

	/**
	 * This test tests if the correct Policy OIDs are returned.
	 * 
	 * The expected result is Bogus With a null the no policy OID is extracted
	 * by the method getPolicyOIDs(). Get policy OIDs when extracted successful,
	 * null if unsuccesfull.
	 */
	@Test
	public void testGetPolicyOIDsBogus() {
		extractorPIP = new ExtractorX509GenericPIP("Bogus", noAcceptedAttributesBogus);
		X509Certificate cert = getCertificateObject(getEndCertificateBogus());

		try {
			extractorPIP.getPolicyOIDs(cert);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals(null, e.getMessage());
			return;
		}
		fail("Test failed!");
	}

	/**
	 * The test tests the method findPEMAttributeForConverson() It returns the
	 * DN if successfull
	 * 
	 * The expected result is "CN=Bla, OU=PDP, O=Example, C=NL" If the method
	 * functions properly, "CN=Bla, OU=PDP, O=Example, C=NL" is returned.
	 */
	@Test
	public void testfindPEMAttributeForConversonSuccess() {
		Set<Attribute> attributes = new LazySet<Attribute>();
		Attribute attribute = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info", Attribute.DT_X500_NAME);
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		attribute.getValues().add(acceptedUserCertificate);

		try {

			attributes.add(attribute);
			X509Certificate[] certChain = extractorPIP.findPEMAttributeForConverson(attributes);
			assertEquals("CN=Bla, OU=PDP, O=Example, C=NL", certChain[0].getSubjectX500Principal().toString());
		} catch (Exception e) {
			 log.debug(e.getMessage());
			fail("Expected a success! Somehow a fail came up!");
		}
		return;
	}

	/**
	 * The test tests the method findPEMAttributeForConverson() It returns the
	 * DN if successfull, otherwise ""The PEM string is not correct!"" is
	 * returned.
	 * 
	 * The expected result is "The PEM string is not correct!" If the method
	 * functions properly, "The PEM string is not correct!" is returned.
	 */
	@Test
	public void testfindPEMAttributeForConversonFailure() {
		Set<Attribute> attributes = new LazySet<Attribute>();
		Attribute attribute = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info", Attribute.DT_X500_NAME);
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		attribute.getValues().add(notAcceptedUserCertificate);

		try {

			attributes.add(attribute);
			extractorPIP.findPEMAttributeForConverson(attributes);
		} catch (Exception e) {
			 log.debug(e.getMessage());
			assertEquals("The PEM string is not correct!", e.getMessage());
			return;
		}

		fail("Expected a failure! Somehow a success came up!");
	}

	/**
	 * The test tests the method findPEMAttributeForConverson() It returns the
	 * DN if successful, otherwise ""The PEM string is not correct!"" is
	 * returned. When no PEM string is inputed, No pem String content in
	 * request! PIP ExtractorX509GenericPIP quited running... is returned.
	 * 
	 * The expected result is No pem String content in request! PIP
	 * ExtractorX509GenericPIP quited running... If the method functions
	 * properly, No pem String content in request! PIP ExtractorX509GenericPIP
	 * quited running... is returned.
	 */
	@Test
	public void testfindPEMAttributeForConversonBogus() {
		Set<Attribute> attributes = new LazySet<Attribute>();
		Attribute attribute = new Attribute("BogusKey-info", Attribute.DT_X500_NAME);
		extractorPIP = new ExtractorX509GenericPIP("BogusID", noAcceptedAttributesBogus);
		attribute.getValues().add(noAcceptedAttributesBogus);

		try {

			attributes.add(attribute);
			extractorPIP.findPEMAttributeForConverson(attributes);
		} catch (Exception e) {
			log.debug(e.getMessage());
			assertEquals("No pem String content in request! PIP ExtractorX509GenericPIP quited running...",
					e.getMessage());
			return;
		}

		fail("Expected a failure! Somehow a success came up!");
	}
}
