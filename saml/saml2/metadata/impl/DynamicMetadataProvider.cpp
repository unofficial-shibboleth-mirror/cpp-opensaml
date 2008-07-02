/*
 *  Copyright 2001-2007 Internet2
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
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>

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
    : AbstractMetadataProvider(e), m_maxCacheDuration(0), m_lock(RWLock::create())
{
    const XMLCh* flag=e ? e->getAttributeNS(NULL,validate) : NULL;
    m_validate=(XMLString::equals(flag,xmlconstants::XML_TRUE) || XMLString::equals(flag,xmlconstants::XML_ONE));
    flag = e ? e->getAttributeNS(NULL,maxCacheDuration) : NULL;
    if (flag && *flag)
        m_maxCacheDuration = XMLString::parseInt(flag);
}

DynamicMetadataProvider::~DynamicMetadataProvider()
{
    // Each entity in the map is unique (no multimap semantics), so this is safe.
    clearDescriptorIndex(true);
    delete m_lock;
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
    else if (criteria.artifact)
        name = criteria.artifact->getSource();
    else
        return entity;

    Category& log = Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic");
    log.info("resolving metadata for (%s)", name.c_str());

    // Try resolving it.
    auto_ptr<EntityDescriptor> entity2(resolve(name.c_str()));

    // Filter it, which may throw.
    doFilters(*entity2.get());

    log.info("caching resolved metadata for (%s)", name.c_str());

    // Translate cacheDuration into validUntil.
    if (entity2->getCacheDuration())
        entity2->setValidUntil(time(NULL) + min(m_maxCacheDuration, entity2->getCacheDurationEpoch()));

    // Upgrade our lock so we can cache the new metadata.
    m_lock->unlock();
    m_lock->wrlock();

    // Notify observers.
    emitChangeEvent();

    // Make sure we clear out any existing copies, including stale metadata or if somebody snuck in.
    index(entity2.release(), SAMLTIME_MAX, true);

    // Downgrade back to a read lock.
    m_lock->unlock();
    m_lock->rdlock();

    // Rinse and repeat.
    return getEntityDescriptor(criteria);
}

EntityDescriptor* DynamicMetadataProvider::resolve(const char* entityID) const
{
    try {
        DOMDocument* doc=NULL;
        auto_ptr_XMLCh widenit(entityID);
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
            "Xerces error while resolving entityID (%s): %s", entityID, msg.get()
            );
        throw MetadataException(msg.get());
    }
    catch (exception& e) {
        Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic").error(
            "error while resolving entityID (%s): %s", entityID, e.what()
            );
        throw;
    }
}
