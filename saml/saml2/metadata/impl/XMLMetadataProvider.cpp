/*
 *  Copyright 2001-2010 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#include <fstream>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

namespace opensaml {
    namespace saml2md {

        class SAML_DLLLOCAL XMLMetadataProvider : public AbstractMetadataProvider, public ReloadableXMLFile
        {
        public:
            XMLMetadataProvider(const DOMElement* e)
                : AbstractMetadataProvider(e), ReloadableXMLFile(e, Category::getInstance(SAML_LOGCAT".MetadataProvider.XML")),
                    m_object(NULL), m_maxCacheDuration(m_reloadInterval) {
            }
            virtual ~XMLMetadataProvider() {
                delete m_object;
            }

            void init() {
                background_load(); // guarantees an exception or the metadata is loaded
            }

            const XMLObject* getMetadata() const {
                return m_object;
            }

        protected:
            pair<bool,DOMElement*> background_load();

        private:
            using AbstractMetadataProvider::index;
            void index();

            XMLObject* m_object;
            time_t m_maxCacheDuration;
        };

        MetadataProvider* SAML_DLLLOCAL XMLMetadataProviderFactory(const DOMElement* const & e)
        {
            return new XMLMetadataProvider(e);
        }

    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

pair<bool,DOMElement*> XMLMetadataProvider::background_load()
{
    // Turn off auto-backup so we can filter first.
    m_backupIndicator = false;

    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it for now.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    // Unmarshall objects, binding the document.
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(raw.second, true));
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

    // If the backup indicator is flipped, then this was a remote load and we need a backup.
    // This is the best place to take a backup, since it's superficially "correct" metadata.
    string backupKey;
    if (m_backupIndicator) {
        // We compute a random filename extension to the "real" location.
        SAMLConfig::getConfig().generateRandomBytes(backupKey, 2);
        backupKey = m_backing + '.' + SAMLArtifact::toHex(backupKey);
        m_log.debug("backing up remote metadata resource to (%s)", backupKey.c_str());
        try {
            ofstream backer(backupKey.c_str());
            backer << *raw.second->getOwnerDocument();
        }
        catch (exception& ex) {
            m_log.crit("exception while backing up metadata: %s", ex.what());
            backupKey.erase();
        }
    }

    try {
        doFilters(*xmlObject.get());
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
    }

    xmlObject->releaseThisAndChildrenDOM();
    xmlObject->setDocument(NULL);

    // Swap it in after acquiring write lock if necessary.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    bool changed = m_object!=NULL;
    delete m_object;
    m_object = xmlObject.release();
    index();
    if (changed)
        emitChangeEvent();

    // If a remote resource, adjust the reload interval if cacheDuration is set.
    if (!m_local) {
        const CacheableSAMLObject* cacheable = dynamic_cast<const CacheableSAMLObject*>(m_object);
        if (cacheable && cacheable->getCacheDuration() && cacheable->getCacheDurationEpoch() < m_maxCacheDuration)
            m_reloadInterval = cacheable->getCacheDurationEpoch();
        else
            m_reloadInterval = m_maxCacheDuration;
    }

    return make_pair(false,(DOMElement*)NULL);
}

void XMLMetadataProvider::index()
{
    clearDescriptorIndex();
    EntitiesDescriptor* group=dynamic_cast<EntitiesDescriptor*>(m_object);
    if (group) {
        AbstractMetadataProvider::index(group, SAMLTIME_MAX);
        return;
    }
    AbstractMetadataProvider::index(dynamic_cast<EntityDescriptor*>(m_object), SAMLTIME_MAX);
}
