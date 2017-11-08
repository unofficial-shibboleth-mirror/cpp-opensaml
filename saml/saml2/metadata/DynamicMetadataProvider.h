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
 * @file saml/saml2/metadata/DynamicMetadataProvider.h
 *
 * Simple implementation of a dynamic caching MetadataProvider.
 */

#ifndef __saml2_absdynmetadataprov_h__
#define __saml2_absdynmetadataprov_h__

#include <saml/saml2/metadata/AbstractDynamicMetadataProvider.h>

namespace opensaml {
    namespace saml2md {

        /**
         * Simple implementation of a dynamic, caching MetadataProvider.
         */
        class SAML_API DynamicMetadataProvider : public AbstractDynamicMetadataProvider
        {
        public:
            /**
             * Constructor.
             *
             * @param e DOM to supply configuration for provider
             */
            DynamicMetadataProvider(const xercesc::DOMElement* e=nullptr);

            void init();

        protected:
            virtual EntityDescriptor* resolve(const Criteria& criteria) const;

        };

    };
};

#endif /* __saml2_dynmetadataprov_h__ */
