/*
 *  Copyright 2001-2009 Internet2
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
 * DynamicMetadataProvider.cpp
 *
 * Simple implementation of a dynamic caching MetadataProvider.
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DynamicMetadataProvider.h"

#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif

static const XMLCh maxCacheDuration[] = UNICODE_LITERAL_16(m,a,x,C,a,c,h,e,D,u,r,a,t,i,o,n);
static const XMLCh validate[] =         UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

namespace opensaml {
    namespace saml2md {
        MetadataProvider* SAML_DLLLOCAL DynamicMetadataProviderFactory(const DOMElement* const & e)
        {
            return new DynamicMetadataProvider(e);
        }
    };
};

DynamicMetadataProvider::DynamicMetadataProvider(const DOMElement* e)
    : AbstractMetadataProvider(e), m_maxCacheDuration(28800), m_lock(RWLock::create())
{
    const XMLCh* flag=e ? e->getAttributeNS(NULL,validate) : NULL;
    m_validate=(XMLString::equals(flag,xmlconstants::XML_TRUE) || XMLString::equals(flag,xmlconstants::XML_ONE));
    flag = e ? e->getAttributeNS(NULL,maxCacheDuration) : NULL;
    if (flag && *flag) {
        m_maxCacheDuration = XMLString::parseInt(flag);
        if (m_maxCacheDuration == 0)
            m_maxCacheDuration = 28800;
    }
}

DynamicMetadataProvider::~DynamicMetadataProvider()
{
    // Each entity in the map is unique (no multimap semantics), so this is safe.
    clearDescriptorIndex(true);
    delete m_lock;
}

const XMLObject* DynamicMetadataProvider::getMetadata() const
{
    throw MetadataException("getMetadata operation not implemented on this provider.");
}

Lockable* DynamicMetadataProvider::lock()
{
    m_lock->rdlock();
    return this;
}

void DynamicMetadataProvider::unlock()
{
    m_lock->unlock();
}

void DynamicMetadataProvider::init()
{
}

pair<const EntityDescriptor*,const RoleDescriptor*> DynamicMetadataProvider::getEntityDescriptor(const Criteria& criteria) const
{
    // Check cache while holding the read lock.
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = AbstractMetadataProvider::getEntityDescriptor(criteria);
    if (entity.first)   // even if the role isn't found, we're done
        return entity;

    string name;
    if (criteria.entityID_ascii)
        name = criteria.entityID_ascii;
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        name = criteria.artifact->getSource();
    }
    else
        return entity;

    Category& log = Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic");
    log.info("resolving metadata for (%s)", name.c_str());

    try {
        // Try resolving it.
        auto_ptr<EntityDescriptor> entity2(resolve(criteria));

        // Verify the entityID.
        if (criteria.entityID_unicode && !XMLString::equals(criteria.entityID_unicode, entity2->getEntityID())) {
            log.error("metadata instance did not match expected entityID");
            return entity;
        }
        else {
            auto_ptr_XMLCh temp2(name.c_str());
            if (!XMLString::equals(temp2.get(), entity2->getEntityID())) {
                log.error("metadata instance did not match expected entityID");
                return entity;
            }
        }

        // Preprocess the metadata (even if we schema-validated).
        try {
            SchemaValidators.validate(entity2.get());
        }
        catch (exception& ex) {
            log.error("metadata intance failed manual validation checking: %s", ex.what());
            throw MetadataException("Metadata instance failed manual validation checking.");
        }

        // Filter it, which may throw.
        doFilters(*entity2.get());

        time_t now = time(NULL);

        if (entity2->getValidUntil() && entity2->getValidUntilEpoch() < now + 60)
            throw MetadataException("Metadata was already invalid at the time of retrieval.");

        log.info("caching resolved metadata for (%s)", name.c_str());

        // Upgrade our lock so we can cache the new metadata.
        m_lock->unlock();
        m_lock->wrlock();

        // Notify observers.
        emitChangeEvent();

        // Make sure we clear out any existing copies, including stale metadata or if somebody snuck in.
        time_t exp = m_maxCacheDuration;
        if (entity2->getCacheDuration())
            exp = min(m_maxCacheDuration, entity2->getCacheDurationEpoch());
        exp += now;
        index(entity2.release(), exp, true);

        // Downgrade back to a read lock.
        m_lock->unlock();
        m_lock->rdlock();
    }
    catch (exception& e) {
        log.error("error while resolving entityID (%s): %s", name.c_str(), e.what());
        return entity;
    }

    // Rinse and repeat.
    return getEntityDescriptor(criteria);
}

EntityDescriptor* DynamicMetadataProvider::resolve(const Criteria& criteria) const
{
    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        throw MetadataException("Unable to resolve metadata dynamically from an artifact.");
    }

    try {
        DOMDocument* doc=NULL;
        auto_ptr_XMLCh widenit(name.c_str());
        URLInputSource src(widenit.get());
        Wrapper4InputSource dsrc(&src,false);
        if (m_validate)
            doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
        else
            doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);

        // Wrap the document for now.
        XercesJanitor<DOMDocument> docjanitor(doc);

        // Unmarshall objects, binding the document.
        auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjanitor.release();

        // Make sure it's metadata.
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(xmlObject.get());
        if (!entity) {
            throw MetadataException(
                "Root of metadata instance not recognized: $1", params(1,xmlObject->getElementQName().toString().c_str())
                );
        }
        xmlObject.release();
        return entity;
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic").error(
            "Xerces error while resolving entityID (%s): %s", name.c_str(), msg.get()
            );
        throw MetadataException(msg.get());
    }
}
