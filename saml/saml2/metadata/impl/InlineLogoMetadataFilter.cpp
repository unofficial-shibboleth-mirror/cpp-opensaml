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
 * InlineLogoMetadataFilter.cpp
 * 
 * Removes inline logos from a metadata instance
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/scoped_ptr.hpp>
#include <xmltooling/logging.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {
        class SAML_DLLLOCAL InlineLogoMetadataFilter : public MetadataFilter
        {
        public:
            InlineLogoMetadataFilter(const DOMElement* e, bool deprecationSupport=true) {}
            ~InlineLogoMetadataFilter() {}
            
            const char* getId() const { return EXCLUDE_METADATA_FILTER; }
            void doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const;

        private:
            void filterGroup(EntitiesDescriptor*) const;
            void filterEntity(EntityDescriptor*) const;
        }; 

        MetadataFilter* SAML_DLLLOCAL InlineLogoMetadataFilterFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            return new InlineLogoMetadataFilter(e);
        }
    };
};


void InlineLogoMetadataFilter::doFilter(const MetadataFilterContext* ctx, XMLObject& xmlObject) const
{
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(&xmlObject);
    if (group) {
        filterGroup(group);
    }
    else {
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(&xmlObject);
        if (entity) {
            filterEntity(entity);
        }
        else {
            throw MetadataFilterException(INLINELOGO_METADATA_FILTER " MetadataFilter was given an improper metadata instance to filter.");
        }
    }
}

void InlineLogoMetadataFilter::filterGroup(EntitiesDescriptor* entities) const
{
    const vector<EntityDescriptor*>& v = const_cast<const EntitiesDescriptor*>(entities)->getEntityDescriptors();
    for_each(v.begin(), v.end(), lambda::bind(&InlineLogoMetadataFilter::filterEntity, this, _1));

    const vector<EntitiesDescriptor*>& v2 = const_cast<const EntitiesDescriptor*>(entities)->getEntitiesDescriptors();
    for_each(v2.begin(), v2.end(), lambda::bind(&InlineLogoMetadataFilter::filterGroup, this, _1));
}

void InlineLogoMetadataFilter::filterEntity(EntityDescriptor* entity) const
{
    static const XMLCh prefix[] = { chLatin_d, chLatin_a, chLatin_t, chLatin_a, chColon, chNull };

    const list<XMLObject*>& children = const_cast<const EntityDescriptor*>(entity)->getOrderedChildren();
    for (list<XMLObject*>::const_iterator child = children.begin(); child != children.end(); ++child) {
        if (dynamic_cast<const RoleDescriptor*>(*child)) {
            const Extensions* ext = dynamic_cast<const RoleDescriptor*>(*child)->getExtensions();
            if (!ext)
                continue;
            const vector<XMLObject*>& exts = ext->getUnknownXMLObjects();
            for (vector<XMLObject*>::const_iterator ext = exts.begin(); ext != exts.end(); ++ext) {
                UIInfo* info = dynamic_cast<UIInfo*>(*ext);
                if (info) {
                    VectorOf(Logo) v = info->getLogos();
                    for (VectorOf(Logo)::size_type i = 0; i < v.size(); ) {
                        const XMLCh* url = v[i]->getURL();
                        if (XMLString::startsWithI(url, prefix)) {
                            v.erase(v.begin() + i);
                        }
                        else {
                            i++;
                        }
                    }

                    break;
                }
            }
        }
    }
}
