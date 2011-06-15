/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file saml/saml2/binding/SAML2Artifact.h
 * 
 * Base class for SAML 2.0 artifacts.
 */

#ifndef __saml2_artifact_h__
#define __saml2_artifact_h__

#include <saml/binding/SAMLArtifact.h>

namespace opensaml {
    namespace saml2p {
        
        /**
         * Base class for SAML 2.0 artifacts.
         */
        class SAML_API SAML2Artifact : public SAMLArtifact
        {
            SAML2Artifact& operator=(const SAML2Artifact& src);
        public:
            virtual ~SAML2Artifact();
            
            /**
             * Returns the endpoint index of the artifact.
             * 
             * @return endpoint index
             */
            virtual int getEndpointIndex() const;
            
            /** Length of endpoint index */            
            static const unsigned int INDEX_LENGTH;

        protected:
            SAML2Artifact();

            /**
             * Constructor.
             * 
             * @param s raw artifact string
             */
            SAML2Artifact(const char* s);
    
            /**
             * Copy constructor.
             * 
             * @param src   object to copy
             */
            SAML2Artifact(const SAML2Artifact& src);
        };
        
    };
};

#endif /* __saml2_artifact_h__ */
