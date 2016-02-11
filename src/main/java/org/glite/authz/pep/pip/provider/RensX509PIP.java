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
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

import java.util.Arrays;
import java.util.List;

/**
 * Created by rens on 9-2-16.
 */
public class RensX509PIP extends AbstractPolicyInformationPoint {
    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(RensX509PIP.class);

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
    public boolean populateRequest(Request request)
            throws PIPProcessingException {
        boolean applied= false;
        
        return applied;
    }

}
