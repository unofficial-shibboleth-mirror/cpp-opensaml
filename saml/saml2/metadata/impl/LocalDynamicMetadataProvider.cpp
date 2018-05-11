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
 * LocalDynamicMetadataProvider.cpp
 *
 * Implementation of a directory base DynamicMetadataProvider.
 */
#include <fstream>

#include <boost/algorithm/string.hpp>


#include "internal.h"

#include <xmltooling/logging.h>
#include <xmltooling/security/SecurityHelper.h>

#include <binding/SAMLArtifact.h>
#include <saml2/metadata/Metadata.h>
#include <saml2/metadata/AbstractDynamicMetadataProvider.h>


#if defined(XMLTOOLING_LOG4SHIB)
# include <log4shib/NDC.hh>
#elif defined(XMLTOOLING_LOG4CPP)
# include <log4cpp/NDC.hh>
#endif

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

static const XMLCh id[] =                   UNICODE_LITERAL_2(i,d);
static const XMLCh sourceDirectory[] =      UNICODE_LITERAL_15(s,o,u,r,c,e,D,i,r,e,c,t,o,r,y);

namespace opensaml {
    namespace saml2md {
        class LocalDynamicMetadataProvider : public AbstractDynamicMetadataProvider {
        public:
            /**
            * Constructor.
            *
            * @param e DOM to supply configuration for provider
            */
            LocalDynamicMetadataProvider(const xercesc::DOMElement* e=nullptr);

            void init() {};

        protected:
            virtual EntityDescriptor* resolve(const Criteria& criteria) const;

        private:
            string m_sourceDirectory;
            Category& m_log;
        };

        MetadataProvider* SAML_DLLLOCAL LocalDynamicMetadataProviderFactory(const DOMElement* const & e)
        {
            return new LocalDynamicMetadataProvider(e);
        }
    };
};

LocalDynamicMetadataProvider::LocalDynamicMetadataProvider(const DOMElement* e)
    : MetadataProvider(e), AbstractDynamicMetadataProvider(false, e),
        m_sourceDirectory(XMLHelper::getAttrString(e, nullptr, sourceDirectory)),
        m_log(Category::getInstance(SAML_LOGCAT ".MetadataProvider.LocalDynamic"))
{
    if (m_sourceDirectory.empty())
        throw  MetadataException("LocalDynamicMetadataProvider: sourceDirectory=\"whatever\" must be present");

    if (!boost::algorithm::ends_with(m_sourceDirectory, "/"))
        m_sourceDirectory += '/';
}

EntityDescriptor* LocalDynamicMetadataProvider::resolve(const Criteria& criteria) const
{
    string name, from;
    if (criteria.entityID_ascii) {
        from = criteria.entityID_ascii;
        name = SecurityHelper::doHash("SHA1", from.c_str(), from.length());
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        from = criteria.entityID_ascii;
        SecurityHelper::doHash("SHA1", from.c_str(), from.length());
    }
    else if (criteria.artifact) {
        from = name = criteria.artifact->getSource();
    }
    name = m_sourceDirectory + name + ".xml";
    m_log.debug("transformed name from (%s) to (%s)", from.c_str(), name.c_str());

    ifstream source(name.c_str());
    if (!source) {
        m_log.debug("local metadata file (%s) not found for input (%s)", name.c_str(), from.c_str());
        throw IOException("Local metadata file not found.");
    }

    EntityDescriptor* result = entityFromStream(source);
    if (!result)
        throw MetadataException("No entity resolved from file."); // shouldn't happen
    return result;
}
