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
 * XMLMetadataProvider.cpp
 *
 * Supplies metadata from an XML file
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"
#include "saml2/metadata/AbstractMetadataProvider.h"
#include "saml2/metadata/DiscoverableMetadataProvider.h"

#include <fstream>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/validation/ValidatorSuite.h>

#if defined(OPENSAML_LOG4SHIB)
# include <log4shib/NDC.hh>
#elif defined(OPENSAML_LOG4CPP)
# include <log4cpp/NDC.hh>
#endif

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

namespace opensaml {
    namespace saml2md {

        class SAML_DLLLOCAL XMLMetadataProvider
            : public AbstractMetadataProvider, public DiscoverableMetadataProvider, public ReloadableXMLFile
        {
        public:
            XMLMetadataProvider(const DOMElement* e);

            virtual ~XMLMetadataProvider() {
                shutdown();
            }

            void init() {
                try {
                    if (!m_id.empty()) {
                        string threadid("[");
                        threadid += m_id + ']';
                        logging::NDC::push(threadid);
                    }
                    background_load();
                    startup();
                }
                catch (...) {
                    startup();
                    if (!m_id.empty()) {
                        logging::NDC::pop();
                    }
                    throw;
                }

                if (!m_id.empty()) {
                    logging::NDC::pop();
                }
            }

            const char* getId() const {
                return m_id.c_str();
            }

            void outputStatus(ostream& os) const {
                os << "<MetadataProvider";

                if (getId() && *getId()) {
                    os << " id='" << getId() << "'";
                }

                if (!m_source.empty()) {
                    os << " source='" << m_source << "'";
                }

                if (m_lastUpdate > 0) {
                    DateTime ts(m_lastUpdate);
                    ts.parseDateTime();
                    auto_ptr_char timestamp(ts.getFormattedString());
                    os << " lastUpdate='" << timestamp.get() << "'";
                }

                if (!m_local && m_reloadInterval > 0) {
                    os << " reloadInterval='" << m_reloadInterval << "'";
                }

                os << "/>";
            }

            const XMLObject* getMetadata() const {
                return m_object.get();
            }

        protected:
            pair<bool,DOMElement*> load(bool backup);
            pair<bool,DOMElement*> background_load();

        private:
            using AbstractMetadataProvider::index;
            void index(time_t& validUntil);
            time_t computeNextRefresh();

            scoped_ptr<XMLObject> m_object;
            bool m_discoveryFeed,m_dropDOM;
            double m_refreshDelayFactor;
            unsigned int m_backoffFactor;
            time_t m_minRefreshDelay,m_maxRefreshDelay,m_lastValidUntil;
        };

        MetadataProvider* SAML_DLLLOCAL XMLMetadataProviderFactory(const DOMElement* const & e)
        {
            return new XMLMetadataProvider(e);
        }

        static const XMLCh discoveryFeed[] =        UNICODE_LITERAL_13(d,i,s,c,o,v,e,r,y,F,e,e,d);
        static const XMLCh dropDOM[] =              UNICODE_LITERAL_7(d,r,o,p,D,O,M);
        static const XMLCh minRefreshDelay[] =      UNICODE_LITERAL_15(m,i,n,R,e,f,r,e,s,h,D,e,l,a,y);
        static const XMLCh refreshDelayFactor[] =   UNICODE_LITERAL_18(r,e,f,r,e,s,h,D,e,l,a,y,F,a,c,t,o,r);
    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

XMLMetadataProvider::XMLMetadataProvider(const DOMElement* e)
    : MetadataProvider(e), AbstractMetadataProvider(e), DiscoverableMetadataProvider(e),
        ReloadableXMLFile(e, Category::getInstance(SAML_LOGCAT".MetadataProvider.XML"), false),
        m_discoveryFeed(XMLHelper::getAttrBool(e, true, discoveryFeed)),
        m_dropDOM(XMLHelper::getAttrBool(e, true, dropDOM)),
        m_refreshDelayFactor(0.75), m_backoffFactor(1),
        m_minRefreshDelay(XMLHelper::getAttrInt(e, 600, minRefreshDelay)),
        m_maxRefreshDelay(m_reloadInterval), m_lastValidUntil(SAMLTIME_MAX)
{
    if (!m_local && m_maxRefreshDelay) {
        const XMLCh* setting = e->getAttributeNS(nullptr, refreshDelayFactor);
        if (setting && *setting) {
            auto_ptr_char delay(setting);
            m_refreshDelayFactor = atof(delay.get());
            if (m_refreshDelayFactor <= 0.0 || m_refreshDelayFactor >= 1.0) {
                m_log.error("invalid refreshDelayFactor setting, using default");
                m_refreshDelayFactor = 0.75;
            }
        }

        if (m_minRefreshDelay > m_maxRefreshDelay) {
            m_log.warn("minRefreshDelay setting exceeds maxRefreshDelay/reloadInterval setting, lowering to match it");
            m_minRefreshDelay = m_maxRefreshDelay;
        }
    }
}

pair<bool,DOMElement*> XMLMetadataProvider::load(bool backup)
{
    if (!backup) {
        // Lower the refresh rate in case of an error.
        m_reloadInterval = m_minRefreshDelay;
    }

    // Call the base class to load/parse the appropriate XML resource.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load(backup);

    // If we own it, wrap it for now.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    // Unmarshall objects, binding the document.
    scoped_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(raw.second, true));
    docjanitor.release();

    if (!dynamic_cast<const EntitiesDescriptor*>(xmlObject.get()) && !dynamic_cast<const EntityDescriptor*>(xmlObject.get()))
        throw MetadataException(
            "Root of metadata instance not recognized: $1", params(1,xmlObject->getElementQName().toString().c_str())
            );

    // Preprocess the metadata (even if we schema-validated).
    try {
        SchemaValidators.validate(xmlObject.get());
    }
    catch (exception& ex) {
        m_log.error("metadata intance failed manual validation checking: %s", ex.what());
        throw MetadataException("Metadata instance failed manual validation checking.");
    }

    const TimeBoundSAMLObject* validityCheck = dynamic_cast<TimeBoundSAMLObject*>(xmlObject.get());
    if (!validityCheck || !validityCheck->isValid()) {
        m_log.error("metadata instance was invalid at time of acquisition");
        throw MetadataException("Metadata instance was invalid at time of acquisition.");
    }

    // This is the best place to take a backup, since it's superficially "correct" metadata.
    string backupKey;
    if (!backup && !m_backing.empty()) {
        // We compute a random filename extension to the "real" location.
        SAMLConfig::getConfig().generateRandomBytes(backupKey, 2);
        backupKey = m_backing + '.' + SAMLArtifact::toHex(backupKey);
        m_log.debug("backing up remote metadata resource to (%s)", backupKey.c_str());
        try {
            ofstream backer(backupKey.c_str());
            backer << *(raw.second->getOwnerDocument());
        }
        catch (exception& ex) {
            m_log.crit("exception while backing up metadata: %s", ex.what());
            backupKey.erase();
        }
    }

    try {
        doFilters(*xmlObject);
    }
    catch (exception&) {
        if (!backupKey.empty())
            remove(backupKey.c_str());
        throw;
    }

    if (!backupKey.empty()) {
        m_log.debug("committing backup file to permanent location (%s)", m_backing.c_str());
        Locker locker(getBackupLock());
        remove(m_backing.c_str());
        if (rename(backupKey.c_str(), m_backing.c_str()) != 0)
            m_log.crit("unable to rename metadata backup file");
        preserveCacheTag();
    }

    if (m_dropDOM) {
        xmlObject->releaseThisAndChildrenDOM();
        xmlObject->setDocument(nullptr);
    }

    // Swap it in after acquiring write lock if necessary.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    bool changed = m_object!=nullptr;
    m_object.swap(xmlObject);
    m_lastValidUntil = SAMLTIME_MAX;
    index(m_lastValidUntil);
    if (m_discoveryFeed)
        generateFeed();
    if (changed)
        emitChangeEvent();
    m_lastUpdate = time(nullptr);

    // Tracking cacheUntil through the tree is TBD, but
    // validUntil is the tightest interval amongst the children.

    // If a remote resource that's monitored, adjust the reload interval.
    if (!backup && !m_local && m_lock) {
        m_backoffFactor = 1;
        m_reloadInterval = computeNextRefresh();
        m_log.info("adjusted reload interval to %d seconds", m_reloadInterval);
    }

    m_loaded = true;
    return make_pair(false,(DOMElement*)nullptr);
}

pair<bool,DOMElement*> XMLMetadataProvider::background_load()
{
    try {
        return load(false);
    }
    catch (long& ex) {
        if (ex == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED) {
            // Unchanged document, so re-establish previous refresh interval.
            m_reloadInterval = computeNextRefresh();
            m_log.info("remote resource (%s) unchanged, adjusted reload interval to %u seconds", m_source.c_str(), m_reloadInterval);
        }
        else {
            // Any other status code, just treat as an error.
            m_reloadInterval = m_minRefreshDelay * m_backoffFactor++;
            if (m_reloadInterval > m_maxRefreshDelay)
                m_reloadInterval = m_maxRefreshDelay;
            m_log.warn("adjusted reload interval to %u seconds", m_reloadInterval);
        }
        if (!m_loaded && !m_backing.empty())
            return load(true);
        throw;
    }
    catch (exception&) {
        if (!m_local) {
            m_reloadInterval = m_minRefreshDelay * m_backoffFactor++;
            if (m_reloadInterval > m_maxRefreshDelay)
                m_reloadInterval = m_maxRefreshDelay;
            m_log.warn("adjusted reload interval to %u seconds", m_reloadInterval);
            if (!m_loaded && !m_backing.empty())
                return load(true);
        }
        throw;
    }
}

time_t XMLMetadataProvider::computeNextRefresh()
{
    time_t now = time(nullptr);

    // If some or all of the metadata is already expired, reload after the minimum.
    if (m_lastValidUntil < now) {
        return m_minRefreshDelay;
    }
    else {
        // Compute the smaller of the validUntil / cacheDuration constraints.
        time_t ret = m_lastValidUntil - now;
        const CacheableSAMLObject* cacheable = dynamic_cast<const CacheableSAMLObject*>(m_object.get());
        if (cacheable && cacheable->getCacheDuration())
            ret = min(ret, cacheable->getCacheDurationEpoch());
            
        // Adjust for the delay factor.
        ret *= m_refreshDelayFactor;

        // Bound by max and min.
        if (ret > m_maxRefreshDelay)
            return m_maxRefreshDelay;
        else if (ret < m_minRefreshDelay)
            return m_minRefreshDelay;

        return ret;
    }
}

void XMLMetadataProvider::index(time_t& validUntil)
{
    clearDescriptorIndex();
    EntitiesDescriptor* group = dynamic_cast<EntitiesDescriptor*>(m_object.get());
    if (group) {
        indexGroup(group, validUntil);
        return;
    }
    indexEntity(dynamic_cast<EntityDescriptor*>(m_object.get()), validUntil);
}
