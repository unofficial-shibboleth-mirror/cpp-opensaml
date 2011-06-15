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
 * NullMetadataProvider.cpp
 * 
 * Dummy provider that returns an empty entity supporting any role.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DynamicMetadataProvider.h"

#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL NullMetadataProvider : public DynamicMetadataProvider
        {
        public:
            NullMetadataProvider(const DOMElement* e) : DynamicMetadataProvider(e), m_template(nullptr) {
                e = XMLHelper::getFirstChildElement(e, samlconstants::SAML20MD_NS, EntityDescriptor::LOCAL_NAME);
                if (e)
                    m_template = dynamic_cast<EntityDescriptor*>(XMLObjectBuilder::buildOneFromElement(const_cast<DOMElement*>(e)));
            }

            virtual ~NullMetadataProvider() {
                delete m_template;
            }

        protected:
            EntityDescriptor* resolve(const char* entityID) const;

        private:
            EntityDescriptor* m_template;
        }; 

        MetadataProvider* SAML_DLLLOCAL NullMetadataProviderFactory(const DOMElement* const & e)
        {
            return new NullMetadataProvider(e);
        }
    };
};

EntityDescriptor* NullMetadataProvider::resolve(const char* entityID) const
{
    // Resolving for us just means fabricating a new dummy element.
    EntityDescriptor* entity = m_template ? m_template->cloneEntityDescriptor() : EntityDescriptorBuilder::buildEntityDescriptor();
    auto_ptr_XMLCh temp(entityID);
    entity->setEntityID(temp.get());
    return entity;
}
