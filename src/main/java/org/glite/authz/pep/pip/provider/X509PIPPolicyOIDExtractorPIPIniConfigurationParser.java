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
 * Created by rens on 9-2-16.
 */
@SuppressWarnings("unused")
public class X509PIPPolicyOIDExtractorPIPIniConfigurationParser implements IniSectionConfigurationParser<PolicyInformationPoint>{

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(X509PIPPolicyOIDExtractorPIPIniConfigurationParser.class);
    
    
   
    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig, AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {
   	 
    	String pipid= iniConfig.getName();

    	X509PIPPolicyOIDExtractor pip= new X509PIPPolicyOIDExtractor(pipid);
     
        return pip;
    }
}
