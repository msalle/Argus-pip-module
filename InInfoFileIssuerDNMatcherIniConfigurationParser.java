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
//#    Rens Visser <rensv@nikhef.nl>
//#    NIKHEF Amsterdam, the Netherlands
//#    <grid-mw-security@nikhef.nl>
//#

package org.glite.authz.pep.pip.provider;

import java.util.Arrays;
import java.util.List;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.x509.X509Attribute;
import eu.emi.security.authn.x509.proxy.OidAndValue;

/**
 * @author Rens Visser
 * @version 1.0
 * @since 1.0
 * 
 *        The ExtractorX509GenericPIPIniConfigurationParser class, is the
 *        Configuration parser for the ExtractorX509GenericPIP PIP.
 */
public class InInfoFileIssuerDNMatcherIniConfigurationParser implements IniSectionConfigurationParser<PolicyInformationPoint> {

	/** Class logger. */
	private Logger log = LoggerFactory.getLogger(InInfoFileIssuerDNMatcherIniConfigurationParser.class);

	/**
	 * The Argus framework makes sure that when a PIP is created, the method
	 * parse() is called. This method is always run.
	 * 
	 * When the PIP is not configured correctly a ConfigurationException is
	 * thrown.
	 * 
	 * @param iniConfig
	 *            Configuration options, pulled from the ini file.
	 * 
	 * @param configBuilder
	 *            An configuration builder.
	 * 
	 * @throws ConfigurationException
	 * 
	 * @return boolean
	 */
	public PolicyInformationPoint parse(Ini.Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
			throws ConfigurationException {
		String pipid = iniConfig.getName();
		InInfoFileIssuerDNMatcher pip = new InInfoFileIssuerDNMatcher(pipid);

		return pip;
	}
}
