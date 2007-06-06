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
 * ArtifactMap.cpp
 * 
 * Helper class for SAMLArtifact mapping and retrieval. 
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ArtifactMap.h"
#include "binding/SAMLArtifact.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLObjectBuilder.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    // In-memory storage of mappings instead of using storage API.
    class SAML_DLLLOCAL ArtifactMappings
    {
    public:
        ArtifactMappings() : m_lock(Mutex::create()) {}
        ~ArtifactMappings() {
            delete m_lock;
            for (map<string,Mapping>::iterator i=m_artMap.begin(); i!=m_artMap.end(); ++i)
                delete i->second.m_xml;
        }
        void storeContent(XMLObject* content, const SAMLArtifact* artifact, const char* relyingParty, int TTL);
        XMLObject* retrieveContent(const SAMLArtifact* artifact, const char* relyingParty);
    
    private:
        struct SAML_DLLLOCAL Mapping {
            Mapping() : m_xml(NULL), m_expires(0) {}
            XMLObject* m_xml;
            string m_relying;
            time_t m_expires;
        };

        void removeMapping(const map<string,Mapping>::iterator& i);
        
        Mutex* m_lock;
        map<string,Mapping> m_artMap;
        multimap<time_t,string> m_expMap;
    };

    static const XMLCh artifactTTL[] =  UNICODE_LITERAL_11(a,r,t,i,f,a,c,t,T,T,L);
    static const XMLCh context[] =      UNICODE_LITERAL_7(c,o,n,t,e,x,t);
    static const XMLCh Mapping[] =      UNICODE_LITERAL_7(M,a,p,p,i,n,g);
    static const XMLCh _relyingParty[] = UNICODE_LITERAL_12(r,e,l,y,i,n,g,P,a,r,t,y);
};

void ArtifactMappings::removeMapping(const map<string,Mapping>::iterator& i)
{
    // Update secondary map.
    pair<multimap<time_t,string>::iterator,multimap<time_t,string>::iterator> range =
        m_expMap.equal_range(i->second.m_expires);
    for (; range.first != range.second; ++range.first) {
        if (range.first->second == i->first) {
            m_expMap.erase(range.first);
            break;
        }
    }
    delete i->second.m_xml;
    m_artMap.erase(i);
}

void ArtifactMappings::storeContent(XMLObject* content, const SAMLArtifact* artifact, const char* relyingParty, int TTL)
{
    Lock wrapper(m_lock);

    // Garbage collect any expired artifacts.
    time_t now=time(NULL);
    multimap<time_t,string>::iterator stop=m_expMap.upper_bound(now);
    for (multimap<time_t,string>::iterator i=m_expMap.begin(); i!=stop; m_expMap.erase(i++)) {
        delete m_artMap[i->second].m_xml;
        m_artMap.erase(i->second);
    }
    
    // Key is the hexed handle.
    string hexed = SAMLArtifact::toHex(artifact->getMessageHandle());
    Mapping& m = m_artMap[hexed];
    m.m_xml = content;
    if (relyingParty)
        m.m_relying = relyingParty;
    m.m_expires = now + TTL;
    m_expMap.insert(pair<const time_t,string>(m.m_expires,hexed));
}

XMLObject* ArtifactMappings::retrieveContent(const SAMLArtifact* artifact, const char* relyingParty)
{
    Category& log=Category::getInstance(SAML_LOGCAT".ArtifactMap");
    Lock wrapper(m_lock);

    map<string,Mapping>::iterator i=m_artMap.find(SAMLArtifact::toHex(artifact->getMessageHandle()));
    if (i==m_artMap.end())
        throw BindingException("Requested artifact not in map or may have expired.");
    
    if (!(i->second.m_relying.empty())) {
        if (!relyingParty || i->second.m_relying != relyingParty) {
            log.warn(
                "request from (%s) for artifact issued to (%s)",
                relyingParty ? relyingParty : "unknown", i->second.m_relying.c_str()
                );
            removeMapping(i);
            throw BindingException("Unauthorized artifact mapping request.");
        }
    }
    
    if (time(NULL) >= i->second.m_expires) {
        removeMapping(i);
        throw BindingException("Requested artifact has expired.");
    }
    
    log.debug("resolved artifact for (%s)", relyingParty ? relyingParty : "unknown");
    XMLObject* ret = i->second.m_xml;
    i->second.m_xml = NULL; // clear member so it doesn't get deleted
    removeMapping(i);
    return ret;
}

ArtifactMap::ArtifactMap(xmltooling::StorageService* storage, const char* context, unsigned int artifactTTL)
    : m_storage(storage), m_context((context && *context) ? context : "opensaml::ArtifactMap"), m_mappings(NULL), m_artifactTTL(artifactTTL)
{
    if (!m_storage)
        m_mappings = new ArtifactMappings();
}

ArtifactMap::ArtifactMap(const DOMElement* e, xmltooling::StorageService* storage)
    : m_storage(storage), m_mappings(NULL), m_artifactTTL(180)
{
    if (e) {
        auto_ptr_char c(e->getAttributeNS(NULL, context));
        if (c.get() && *c.get())
            m_context = c.get();
        else
            m_context = "opensaml::ArtifactMap";
        
        const XMLCh* TTL = e->getAttributeNS(NULL, artifactTTL);
        if (TTL) {
            m_artifactTTL = XMLString::parseInt(TTL);
            if (!m_artifactTTL)
                m_artifactTTL = 180;
        }
    }
    
    if (!m_storage)
        m_mappings = new ArtifactMappings();
}

ArtifactMap::~ArtifactMap()
{
    delete m_mappings;
}

void ArtifactMap::storeContent(XMLObject* content, const SAMLArtifact* artifact, const char* relyingParty)
{
    if (content->getParent())
        throw BindingException("Cannot store artifact mapping for XML content with parent.");
    else if (!m_storage)
        return m_mappings->storeContent(content, artifact, relyingParty, m_artifactTTL);
    
    // Marshall with defaulted document, to reuse existing DOM and/or create a bound Document.
    DOMElement* root = content->marshall();
    
    // Build a DOM with the same document to store the relyingParty mapping.
    if (relyingParty) {
        auto_ptr_XMLCh temp(relyingParty);
        root = root->getOwnerDocument()->createElementNS(NULL,Mapping);
        root->setAttributeNS(NULL,_relyingParty,temp.get());
        root->appendChild(content->getDOM());
    }
    
    // Serialize the root element, whatever it is, for storage.
    string xmlbuf;
    XMLHelper::serialize(root, xmlbuf);
    m_storage->createText(
        m_context.c_str(), SAMLArtifact::toHex(artifact->getMessageHandle()).c_str(), xmlbuf.c_str(), time(NULL) + m_artifactTTL
        );
        
    // Cleanup by destroying XML.
    delete content;
}

XMLObject* ArtifactMap::retrieveContent(const SAMLArtifact* artifact, const char* relyingParty)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("retrieveContent");
#endif

    if (!m_storage)
        return m_mappings->retrieveContent(artifact, relyingParty);
    
    string xmlbuf;
    string key = SAMLArtifact::toHex(artifact->getMessageHandle());
    if (!m_storage->readText(m_context.c_str(), key.c_str(), &xmlbuf))
        throw BindingException("Artifact not found in mapping database.");
    
    istringstream is(xmlbuf);
    DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(is);
    XercesJanitor<DOMDocument> janitor(doc);

    Category& log=Category::getInstance(SAML_LOGCAT".ArtifactMap");
    m_storage->deleteText(m_context.c_str(), key.c_str());
    
    // Check the root element.
    DOMElement* messageRoot = doc->getDocumentElement();
    if (XMLHelper::isNodeNamed(messageRoot, NULL, Mapping)) {
        auto_ptr_char temp(messageRoot->getAttributeNS(NULL,_relyingParty));
        if (!relyingParty || strcmp(temp.get(),relyingParty)) {
            log.warn("request from (%s) for artifact issued to (%s)", relyingParty ? relyingParty : "unknown", temp.get());
            throw BindingException("Unauthorized artifact mapping request.");
        }
        messageRoot = XMLHelper::getFirstChildElement(messageRoot);
    }
    
    // Unmarshall...
    XMLObject* xmlObject = XMLObjectBuilder::buildOneFromElement(messageRoot, true);    // bind document
    janitor.release();
    
    log.debug("resolved artifact for (%s)", relyingParty ? relyingParty : "unknown");
    return xmlObject;
}
