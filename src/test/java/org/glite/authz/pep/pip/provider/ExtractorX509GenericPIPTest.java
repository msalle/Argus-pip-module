/**
 * 
 */
package org.glite.authz.pep.pip.provider;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.LazySet;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.io.FileUtils;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

import org.glite.authz.pep.pip.PIPProcessingException;

/**
 * @author Rens
 *
 */
public class ExtractorX509GenericPIPTest {
	ExtractorX509GenericPIP extractorPIP = null;
	private final Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIPTest.class);
	String[] noAcceptedAttributes;
	String[] acceptedAttributes;
	String acceptedUserCertificate, notAcceptedUserCertificate;
	Request globalRequest = new Request();

	private String getContents(String fileName) throws IOException {
		System.out.println(FileUtils.readFileToString(new File(fileName)));
		return FileUtils.readFileToString(new File(fileName));
	}

	private X509Certificate getCertificateObject(String fileName) {
		InputStream inStream = null;
		X509Certificate cert = null;
		try {
			inStream = new FileInputStream(fileName);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) cf.generateCertificate(inStream);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		} finally {
			try {
				if (inStream != null) {
					inStream.close();
				}
			} catch (Exception e2) {
				System.out.println(e2.getMessage());
			}
		}
		return cert;
	}

	/**
	 * Used to set up resources used in the test.
	 */
	@Before
	public void initialize() {
		noAcceptedAttributes = new String[5];
		acceptedAttributes = new String[2];
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

		acceptedAttributes[0] = "http://authz-interop.org/xacml/subject/ca-policy-oid";
		acceptedAttributes[1] = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

		Set<Subject> subjects = globalRequest.getSubjects();

		try {
			acceptedUserCertificate = getContents("/home/rens/.globus/usercer2.pem");
			notAcceptedUserCertificate = getContents("/home/rens/.globus/usercer2fake.pem");

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
			e.getMessage();
		}
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#ExtractorX509GenericPIP(java.lang.String, java.lang.String[])}
	 * . This test should fail, only null is passed to class constructor.
	 */
	@Test
	public void testOneExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(null, null);
		} catch (Exception e) {
			log.debug("Debug line: " + e.getMessage());
			System.out.println("Debug line: " + e.getMessage());
			// assertTrue(true);
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#ExtractorX509GenericPIP(java.lang.String, java.lang.String[])}
	 * . This test should fail, only null is passed to class constructor.
	 */
	@Test
	public void testTwoExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP("", null);
		} catch (Exception e) {
			log.debug("Debug line: " + e.getMessage());
			// assertTrue(true);
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#ExtractorX509GenericPIP(java.lang.String, java.lang.String[])}
	 * . This test should fail, only null is passed to class constructor.
	 */
	@Test
	public void testTreeExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(null, new String[20]);
		} catch (Exception e) {
			log.debug("Debug line: " + e.getMessage());
			// assertTrue(true);
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#ExtractorX509GenericPIP(java.lang.String, java.lang.String[])}
	 * . This test should fail, only null is passed to class constructor.
	 */
	@Test
	public void testFourExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP("", acceptedAttributes);
		} catch (Exception e) {
			log.debug("Debug line: " + e.getMessage());
			// assertTrue(true);
			return;
		}
		fail("Expected a exception.");
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#ExtractorX509GenericPIP(java.lang.String, java.lang.String[])}
	 * . This test should fail, only null is passed to class constructor.
	 */
	@Test
	public void testFiveExtractorX509GenericPIP() {

		try {
			extractorPIP = new ExtractorX509GenericPIP(
					"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
					acceptedAttributes);
		} catch (Exception e) {
			log.debug("Debug line: " + e.getMessage());
			fail(e.getMessage());
		}
		// assertTrue(true);
		return;
	}

	/**
	 * Test method for
	 * {@link org.glite.authz.pep.pip.provider.ExtractorX509GenericPIP#populateRequest(org.glite.authz.common.model.Request)}
	 * . Test shouls succeed sinc eonly allowed attributes are passed.
	 */
	@Test
	public void testAcceptedIDsPopulateRequest() {
		try {
			extractorPIP = new ExtractorX509GenericPIP(
					"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
					acceptedAttributes);
			extractorPIP.populateRequest(globalRequest);
		} catch (Exception e) {
			fail("Expected a succes! Somehow a error got thrown");
		}
		return;
	}

	/**
	 * This test should fail, only false attributes are passed to class
	 * constructor.
	 */
	@Test
	public void testNoAcceptedIDsPopulateRequest() {
		try {
			extractorPIP = new ExtractorX509GenericPIP("ssvdkjsvfdkdsdvs@%^&*()_+-=", noAcceptedAttributes);
			extractorPIP.populateRequest(globalRequest);
		} catch (Exception e) {
			return;
		}
		fail("Expected a fail! Somehow a success is returned");
	}

	@Test
	public void testGetPolicyOIDsSuccess() {
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		X509Certificate cert = getCertificateObject("/home/rens/.globus/usercer2.pem");

		try {
			extractorPIP.getPolicyOIDs(cert);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		return;
	}

	@Test
	public void testGetPolicyOIDsFailure() {
		extractorPIP = new ExtractorX509GenericPIP(
				"ssvdkjsvfdkdsdvs@kbfkff!@#$%^&*()qwertyuiop[]asdfghjkl;'zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?!@#$%^&*()_+-=",
				acceptedAttributes);
		X509Certificate cert = getCertificateObject("/home/rens/.globus/usercer2fake.pem");

		try {
			extractorPIP.getPolicyOIDs(cert);
		} catch (Exception e) {
			e.getMessage();
			return;
		}
		fail("Test failed!");
	}

	/**
	 * Test for if attribute can be found. Test must succeed
	 * 
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
			extractorPIP.findPEMAttributeForConverson(attributes);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			fail("Expected a success! Somehow a fail came up!");
		}
		return;
	}

	/**
	 * Test for if attribute can be found. Test must succeed
	 * 
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
			System.out.println(e.getMessage());
			return;
		}

		fail("Expected a failure! Somehow a success came up!");
	}
}
