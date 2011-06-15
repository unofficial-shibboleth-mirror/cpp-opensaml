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
 * RequireValidUntilMetadataFilter.cpp
 * 
 * MetadataFilter that enforces expiration requirements.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
                
        class SAML_DLLLOCAL RequireValidUntilMetadataFilter : public MetadataFilter
        {
        public:
            RequireValidUntilMetadataFilter(const DOMElement* e);
            ~RequireValidUntilMetadataFilter() {}
            
            const char* getId() const { return REQUIREVALIDUNTIL_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            time_t m_maxValidityInterval;
        }; 

        MetadataFilter* SAML_DLLLOCAL RequireValidUntilMetadataFilterFactory(const DOMElement* const & e)
        {
            return new RequireValidUntilMetadataFilter(e);
        }

    };
};

static const XMLCh maxValidityInterval[] =  UNICODE_LITERAL_19(m,a,x,V,a,l,i,d,i,t,y,I,n,t,e,r,v,a,l);

RequireValidUntilMetadataFilter::RequireValidUntilMetadataFilter(const DOMElement* e)
    : m_maxValidityInterval(XMLHelper::getAttrInt(e, 60 * 60 * 24 * 7, maxValidityInterval))
{
}

void RequireValidUntilMetadataFilter::doFilter(XMLObject& xmlObject) const
{
    const TimeBoundSAMLObject* tbo = dynamic_cast<const TimeBoundSAMLObject*>(&xmlObject);
    if (!tbo)
        throw MetadataFilterException("Metadata root element was invalid.");

    if (!tbo->getValidUntil())
        throw MetadataFilterException("Metadata did not include a validUntil attribute.");

    if (tbo->getValidUntilEpoch() - time(nullptr) > m_maxValidityInterval)
        throw MetadataFilterException("Metadata validity interval is larger than permitted.");
}
