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

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "internal.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/XMLHelper.h>

#include <binding/SAMLArtifact.h>
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
            virtual EntityDescriptor* resolve(const Criteria& criteria, string& cacheTag) const;

        private:
            Category& m_log;
            string m_sourceDirectory;
        };

        MetadataProvider* SAML_DLLLOCAL LocalDynamicMetadataProviderFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            return new LocalDynamicMetadataProvider(e);
        }
    };
};

LocalDynamicMetadataProvider::LocalDynamicMetadataProvider(const DOMElement* e)
    : MetadataProvider(e), AbstractDynamicMetadataProvider(false, e),
        m_log(Category::getInstance(SAML_LOGCAT ".MetadataProvider.LocalDynamic")),
        m_sourceDirectory(XMLHelper::getAttrString(e, nullptr, sourceDirectory))
{
    if (m_sourceDirectory.empty())
        throw  MetadataException("LocalDynamicMetadataProvider: sourceDirectory=\"whatever\" must be present");

    XMLToolingConfig::getConfig().getPathResolver()->resolve(m_sourceDirectory, PathResolver::XMLTOOLING_CFG_FILE);

    if (!boost::algorithm::ends_with(m_sourceDirectory, "/"))
        m_sourceDirectory += '/';
}

EntityDescriptor* LocalDynamicMetadataProvider::resolve(const Criteria& criteria, string& cacheTag) const
{
    string name, from;
    if (criteria.entityID_ascii) {
        from = criteria.entityID_ascii;
        name = SecurityHelper::doHash("SHA1", from.c_str(), from.length());
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        from = temp.get();
        name = SecurityHelper::doHash("SHA1", from.c_str(), from.length());
    }
    else if (criteria.artifact) {
        from = name = criteria.artifact->getSource();
    }
    name = m_sourceDirectory + name + ".xml";
    m_log.debug("transformed name from (%s) to (%s)", from.c_str(), name.c_str());

    time_t lastaccess;
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(name.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(name.c_str(), &stat_buf) == 0)
#endif
        lastaccess = stat_buf.st_mtime;
    else
        throw IOException("Unable to access local file ($1)", params(1, name.c_str()));

    // Note that we're at minimum under a read lock here overall, which precludes the cleanup
    // thread in the base class from running a cleanup pass, and potentially invalidating
    // state during this evaluation. That should prevent a race condition where we determine
    // no update is needed but the original copy is purged before the query finishes.

    try {
        string newCacheTag = boost::lexical_cast<string>(lastaccess);
        if (cacheTag == newCacheTag)
            return nullptr;
        cacheTag = newCacheTag;
    }
    catch (const boost::bad_lexical_cast& e) {
        m_log.error("exception converting between cache tag and access time: %s", e.what());
        cacheTag = "";
    }

    ifstream source(name.c_str());
    if (!source) {
        m_log.debug("local metadata file (%s) not accessible for input (%s)", name.c_str(), from.c_str());
        throw IOException("Unable to access local file ($1)", params(1, name.c_str()));
    }

    EntityDescriptor* result = entityFromStream(source);
    if (!result)
        throw MetadataException("No entity resolved from file."); // shouldn't happen

    return result;
}
