//# Copyright (c) FOM-Nikhef 2016-
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
import java.util.ArrayList;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PIPProcessingException;
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
public class ExtractorX509GenericPIPIniConfigurationParser
		implements IniSectionConfigurationParser<PolicyInformationPoint> {

	/** Class logger. */
	private Logger log = LoggerFactory.getLogger(ExtractorX509GenericPIPIniConfigurationParser.class);

	/**
	 * String of text used in the configuration of the PIP: acceptedProfileIDs.
	 */
	protected static String ACCEPTED_PROFILE_IDS_PROP = "acceptedAttributeIDs";

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
		// read accepted profile IDs from configuration.
		String[] acceptedProfileIds = parseValuesList(iniConfig.get(ACCEPTED_PROFILE_IDS_PROP));
		ExtractorX509GenericPIP pip = new ExtractorX509GenericPIP(pipid, acceptedProfileIds);

		return pip;
	}

	/**
	 * Parses a space delimited list of values.
	 * 
	 * @param valuesList
	 *            space delimited list of values, may be <code>null</code>.
	 * 
	 * @return array of values or <code>null</code> if valuesList is
	 *         <code>null</code>
	 */
	private String[] parseValuesList(String valuesList) {
		if (valuesList == null) {
			return null;
		}
		return valuesList.trim().split("\\s");
	}
}
