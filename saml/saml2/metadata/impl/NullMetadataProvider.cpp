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
#include "saml2/metadata/AbstractDynamicMetadataProvider.h"

#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

using boost::scoped_ptr;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL NullMetadataProvider : public AbstractDynamicMetadataProvider
        {
        public:
            NullMetadataProvider(const DOMElement* e) : AbstractDynamicMetadataProvider(true, e), MetadataProvider(e) {
                e = XMLHelper::getFirstChildElement(e, samlconstants::SAML20MD_NS, EntityDescriptor::LOCAL_NAME);
                if (e)
                    m_template.reset(dynamic_cast<EntityDescriptor*>(XMLObjectBuilder::buildOneFromElement(const_cast<DOMElement*>(e))));
            }

            virtual ~NullMetadataProvider() {}

            void init() {}

        protected:
            EntityDescriptor* resolve(const MetadataProvider::Criteria& criteria, string& cacheTag) const;

        private:
            scoped_ptr<EntityDescriptor> m_template;
        }; 

        MetadataProvider* SAML_DLLLOCAL NullMetadataProviderFactory(const DOMElement* const & e)
        {
            return new NullMetadataProvider(e);
        }
    };
};

EntityDescriptor* NullMetadataProvider::resolve(const MetadataProvider::Criteria& criteria, string& cacheTag) const
{
    // Resolving for us just means fabricating a new dummy element.
    EntityDescriptor* entity = m_template.get() ? m_template->cloneEntityDescriptor() : EntityDescriptorBuilder::buildEntityDescriptor();

    if (criteria.entityID_ascii) {
        auto_ptr_XMLCh temp(criteria.entityID_ascii);
        entity->setEntityID(temp.get());
    }
    else if (criteria.entityID_unicode)
        entity->setEntityID(criteria.entityID_unicode);
    else if (criteria.artifact)
            throw MetadataException("Unable to resolve Null metadata from an artifact.");
    return entity;
}
