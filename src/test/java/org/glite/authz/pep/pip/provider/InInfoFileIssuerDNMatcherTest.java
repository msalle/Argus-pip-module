package org.glite.authz.pep.pip.provider;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.LazySet;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.io.FileUtils;

/**
 * Class to test the InInfoFileIssuerDNMatcher class.
 * @author rens
 *
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
	 * This method is used to get the contents of a file in String
	 * representation. The method assumes a full path to the file is provided.
	 * 
	 * @param filePathName Fullpath of the wanted file
	 * @return The content of the requested file
	 * @throws IOException
	 */
	private String getContents(String filePathName) throws IOException {
		return FileUtils.readFileToString(new File(filePathName));
	}

	/**
	 * Used to set up resources used in the test.
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

			correctIssuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
			correctIssuerDNInformation.setDataType(Attribute.DT_STRING);
			correctIssuerDNInformation.getValues().add("/C=NL/O=Example/OU=PDP/CN=rootCA");

			incorrectIssuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
			incorrectIssuerDNInformation.setDataType(Attribute.DT_STRING);
			incorrectIssuerDNInformation.getValues().add("RandomString");

			pemString.getValues().add(getContents("/home/rens/.globus/usercer2.pem"));

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
	 *  All input is correct, the class is used as a whitebox test, for the entire class.
	 */
	@Test
	public void testPopulateRequestSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		Boolean b;
		try {
			b = InInfoFileIssuerDNMatcherPIP.populateRequest(globalRequest);
			if (b) {
				return;
			} else {
				fail("Expected a true");
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}

	}

	/**
	 * All input is false, the class is used as a whitebox test, for the entire class.
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

			incorrectIssuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
			incorrectIssuerDNInformation.setDataType(Attribute.DT_STRING);
			incorrectIssuerDNInformation.getValues().add("RandomString");

			pemString.getValues().add(getContents("/home/rens/.globus/usercer2.pem"));

			subjectAttributes.add(incorrectIssuerDNInformation);
			subjectAttributes.add(pemString);
			subjectAttributes.add(policyOID);
			sub.getAttributes().addAll(subjectAttributes);
			subjects.add(sub);
			globalRequest.getSubjects().addAll(subjects);
		} catch (Exception e) {

		}

		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		Boolean b;
		try {
			b = InInfoFileIssuerDNMatcherPIP.populateRequest(globalRequest);
			if (b) {
				fail("Expected a false");
			} else {
				return;
			}
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	/**
	 * All input is correct, the class is used as a whitebox test, for the method.
	 */
	@Test
	public void testGetIssuerDNFromSubjectSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		Attribute issuerDNInformation = new Attribute("http://authz-interop.org/xacml/subject/subject-x509-issuer");
		issuerDNInformation.setDataType(Attribute.DT_STRING);
		issuerDNInformation.getValues()
				.add("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3");
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		subjectAttributes.add(issuerDNInformation);

		if (InInfoFileIssuerDNMatcherPIP.getIssuerDNFromSubject(subjectAttributes)
				.equals("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3")) {
			return;
		} else {
			fail("Expected a string back");
		}
	}

	/**
	 * All input is false, the class is used as a whitebox test, for the method.
	 */
	@Test
	public void testGetIssuerDNFromSubjectFailure() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		Attribute issuerDNInformation = new Attribute("ttp://authz-interop.org/xacml/subject/ca-policy-oid");
		issuerDNInformation.setDataType(Attribute.DT_STRING);
		issuerDNInformation.getValues()
				.add("/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3");
		Set<Attribute> subjectAttributes = new LazySet<Attribute>();
		subjectAttributes.add(issuerDNInformation);
		try {
			if (InInfoFileIssuerDNMatcherPIP.getIssuerDNFromSubject(subjectAttributes).equals(null)) {
				return;
			} else {
				fail("Expected a Null back");
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}

	/**
	 * All input is correct, the class is used as a whitebox test, for the method.
	 */
	@Test
	public void testIssuerDNParserSuccess() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		InInfoFileIssuerDNMatcherPIP.CertificateIssuerDN = "/C=NL/O=Example/OU=PDP/CN=rootCA";
		try {
			if (InInfoFileIssuerDNMatcherPIP.issuerDNParser("/etc/grid-security/certificates/rootCA.info")) {
				return;
			} else {
				fail("Expected a true!");
			}
		} catch (Exception e) {
			e.getMessage();
		}
	}

	/**
	 * All input is false, the class is used as a whitebox test, for the method.
	 */
	@Test
	public void testIssuerDNParserFailure() {
		InInfoFileIssuerDNMatcherPIP = new InInfoFileIssuerDNMatcher("asdasdasd");
		InInfoFileIssuerDNMatcherPIP.CertificateIssuerDN = "/C=NL/O=Example/OU=PDP/CN=rootCA";
		try {
			if (InInfoFileIssuerDNMatcherPIP
					.issuerDNParser("/etc/grid-security/certificates/AAACertificateServices.info")) {

				fail("Expected a false!!");
			} else {
				return;
			}
		} catch (Exception e) {
			e.getMessage();
		}
	}
}
