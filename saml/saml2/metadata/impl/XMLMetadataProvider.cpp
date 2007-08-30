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
 * XMLMetadataProvider.cpp
 * 
 * Supplies metadata from an XML file
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"
#include "saml2/metadata/AbstractMetadataProvider.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>

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
                    m_object(NULL) {
            }
            virtual ~XMLMetadataProvider() {
                delete m_object;
            }

            void init() {
                load(); // guarantees an exception or the metadata is loaded
            }
            
            const XMLObject* getMetadata() const {
                return m_object;
            }

        protected:
            pair<bool,DOMElement*> load();

        private:
            using AbstractMetadataProvider::index;
            void index();
        
            XMLObject* m_object;
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

pair<bool,DOMElement*> XMLMetadataProvider::load()
{
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
    
    // Preprocess the metadata.
    doFilters(*xmlObject.get());
    xmlObject->releaseThisAndChildrenDOM();
    xmlObject->setDocument(NULL);
    
    // Swap it in.
    bool changed = m_object!=NULL;
    delete m_object;
    m_object = xmlObject.release();
    index();
    if (changed)
        emitChangeEvent();
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
    EntityDescriptor* site=dynamic_cast<EntityDescriptor*>(m_object);
    AbstractMetadataProvider::index(site, SAMLTIME_MAX);
}
