/*
 *  Copyright 2001-2006 Internet2
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
 * FilesystemMetadataProvider.cpp
 * 
 * Supplies metadata from a local file, detecting and reloading changes.
 */

#include "internal.h"
#include "saml2/metadata/MetadataProvider.h"

#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <log4cpp/Category.hh>
#include <xercesc/framework/LocalFileInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2md {
        
        
        class SAML_DLLLOCAL FilesystemMetadataProvider : public MetadataProvider
        {
        public:
            FilesystemMetadataProvider(const DOMElement* e);
            ~FilesystemMetadataProvider();

            Lockable* lock();
            void unlock() {
                if (m_lock)
                    m_lock->unlock();
            }

            void init();

            const EntityDescriptor* lookup(const XMLCh* id, bool requireValidMetadata=true) const;
            const EntityDescriptor* lookup(const char* id, bool requireValidMetadata=true) const;
            const EntitiesDescriptor* lookupGroup(const XMLCh* name, bool requireValidMetadata=true) const;
            const EntitiesDescriptor* lookupGroup(const char* name, bool requireValidMetadata=true) const;

        private:
            XMLObject* load() const;
            void index();
            void index(EntityDescriptor* site, time_t validUntil=LLONG_MAX);
            void index(EntitiesDescriptor* group, time_t validUntil=LLONG_MAX);
        
            // index of loaded metadata
            typedef multimap<string,const EntityDescriptor*> sitemap_t;
            typedef multimap<string,const EntitiesDescriptor*> groupmap_t;
            sitemap_t m_sites;
            sitemap_t m_sources;
            groupmap_t m_groups;

            const DOMElement* m_root; // survives only until init() method is done
            std::string m_source;
            time_t m_filestamp;
            bool m_validate;
            RWLock* m_lock;
            XMLObject* m_object;
        }; 

        MetadataProvider* SAML_DLLLOCAL FilesystemMetadataProviderFactory(const DOMElement* const & e)
        {
            return new FilesystemMetadataProvider(e);
        }

    };
};

static const XMLCh uri[] =      UNICODE_LITERAL_3(u,r,i);
static const XMLCh url[] =      UNICODE_LITERAL_3(u,r,l);
static const XMLCh path[] =     UNICODE_LITERAL_4(p,a,t,h);
static const XMLCh pathname[] = UNICODE_LITERAL_8(p,a,t,h,n,a,m,e);
static const XMLCh file[] =     UNICODE_LITERAL_4(f,i,l,e);
static const XMLCh filename[] = UNICODE_LITERAL_8(f,i,l,e,n,a,m,e);
static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

FilesystemMetadataProvider::FilesystemMetadataProvider(const DOMElement* e)
    : m_root(e), m_filestamp(0), m_validate(false), m_lock(NULL), m_object(NULL)
{
#ifdef _DEBUG
    NDC ndc("FilesystemMetadataProvider");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata");

    // Establish source of data...
    const XMLCh* source=e->getAttributeNS(NULL,uri);
    if (!source || !*source) {
        source=e->getAttributeNS(NULL,url);
        if (!source || !*source) {
            source=e->getAttributeNS(NULL,path);
            if (!source || !*source) {
                source=e->getAttributeNS(NULL,pathname);
                if (!source || !*source) {
                    source=e->getAttributeNS(NULL,file);
                    if (!source || !*source) {
                        source=e->getAttributeNS(NULL,filename);
                    }
                }
            }
        }
    }
    
    if (source && *source) {
        const XMLCh* valflag=e->getAttributeNS(NULL,validate);
        m_validate=(XMLString::equals(valflag,XMLConstants::XML_TRUE) || XMLString::equals(valflag,XMLConstants::XML_ONE));
        
        auto_ptr_char temp(source);
        m_source=temp.get();
        log.debug("using external metadata file (%s)", temp.get());

#ifdef WIN32
        struct _stat stat_buf;
        if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
        struct stat stat_buf;
        if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
            m_filestamp=stat_buf.st_mtime;
        m_lock=RWLock::create();
    }
    else
        log.debug("no file path/name supplied, will look for metadata inline");
}

FilesystemMetadataProvider::~FilesystemMetadataProvider()
{
    delete m_lock;
    delete m_object;
}

void FilesystemMetadataProvider::init()
{
    m_object=load();
    index();
}

XMLObject* FilesystemMetadataProvider::load() const
{
#ifdef _DEBUG
    NDC ndc("load");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata");
    
    try {
        XMLObject* xmlObject=NULL;
        
        if (!m_source.empty()) {
            // Data comes from a file we have to parse.
            log.debug("loading metadata from file...");
            auto_ptr_XMLCh widenit(m_source.c_str());
            LocalFileInputSource src(widenit.get());
            Wrapper4InputSource dsrc(&src,false);
            DOMDocument* doc=NULL;
            if (m_validate)
                doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
            else
                doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);
            XercesJanitor<DOMDocument> docjanitor(doc);
            log.infoStream() << "loaded and parsed XML file (" << m_source << ")" << CategoryStream::ENDLINE;
            
            // Unmarshall objects, binding the document.
            xmlObject = XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true);
            docjanitor.release();
        }
        else {
            // Data comes from the DOM we were handed.
            log.debug("loading inline metadata...");
            DOMElement* child = XMLHelper::getFirstChildElement(m_root);
            if (!child)
                throw XMLToolingException("No metadata was found inline.");
            xmlObject = XMLObjectBuilder::buildOneFromElement(child);
        }
        
        auto_ptr<XMLObject> xmlObjectPtr(xmlObject);
        
        if (m_filter) {
            log.info("applying metadata filter (%s)", m_filter->getId());
            m_filter->doFilter(*xmlObject);
        }
        
        xmlObjectPtr->releaseThisAndChildrenDOM();
        xmlObjectPtr->setDocument(NULL);
        return xmlObjectPtr.release();
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        log.errorStream() << "Xerces parser error while loading metadata from ("
            << (m_source.empty() ? "inline" : m_source) << "): " << msg.get() << CategoryStream::ENDLINE;
        throw XMLParserException(msg.get());
    }
    catch (XMLToolingException& e) {
        log.errorStream() << "error while loading metadata from ("
            << (m_source.empty() ? "inline" : m_source) << "): " << e.what() << CategoryStream::ENDLINE;
        throw;
    }
}

Lockable* FilesystemMetadataProvider::lock()
{
    if (!m_lock)
        return this;
        
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime) {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime) {
                SharedLock lockwrap(m_lock,false);  // pops write lock
                try {
                    // Update the timestamp regardless. No point in repeatedly trying.
                    m_filestamp=stat_buf.st_mtime;
                    XMLObject* newstuff = load();
                    delete m_object;
                    m_object = newstuff;
                    index();
                }
                catch(XMLToolingException& e) {
                    Category::getInstance(SAML_LOGCAT".Metadata").error("failed to reload metadata from file, sticking with what we have: %s", e.what());
                }
            }
            else {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
    return this;
}

void FilesystemMetadataProvider::index()
{
    m_sources.clear();
    m_sites.clear();
    m_groups.clear();
    
    EntitiesDescriptor* group=dynamic_cast<EntitiesDescriptor*>(m_object);
    if (group) {
        index(group);
        return;
    }
    EntityDescriptor* site=dynamic_cast<EntityDescriptor*>(m_object);
    index(site);
}

void FilesystemMetadataProvider::index(EntityDescriptor* site, time_t validUntil)
{
    if (validUntil < site->getValidUntilEpoch())
        site->setValidUntil(validUntil);

    auto_ptr_char id(site->getEntityID());
    if (id.get()) {
        m_sites.insert(make_pair(id.get(),site));
    }
}

void FilesystemMetadataProvider::index(EntitiesDescriptor* group, time_t validUntil)
{
    if (validUntil < group->getValidUntilEpoch())
        group->setValidUntil(validUntil);

    auto_ptr_char name(group->getName());
    if (name.get()) {
        m_groups.insert(make_pair(name.get(),group));
    }
    
    const vector<EntitiesDescriptor*>& groups=const_cast<const EntitiesDescriptor*>(group)->getEntitiesDescriptors();
    for (vector<EntitiesDescriptor*>::const_iterator i=groups.begin(); i!=groups.end(); i++)
        index(*i,group->getValidUntilEpoch());

    const vector<EntityDescriptor*>& sites=const_cast<const EntitiesDescriptor*>(group)->getEntityDescriptors();
    for (vector<EntityDescriptor*>::const_iterator j=sites.begin(); j!=sites.end(); j++)
        index(*j,group->getValidUntilEpoch());
}

const EntitiesDescriptor* FilesystemMetadataProvider::lookupGroup(const char* name, bool strict) const
{
    pair<groupmap_t::const_iterator,groupmap_t::const_iterator> range=m_groups.equal_range(name);

    time_t now=time(NULL);
    for (groupmap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;
    
    if (!strict && range.first!=range.second)
        return range.first->second;
        
    return NULL;
}

const EntitiesDescriptor* FilesystemMetadataProvider::lookupGroup(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return lookupGroup(temp.get(),strict);
}

const EntityDescriptor* FilesystemMetadataProvider::lookup(const char* name, bool strict) const
{
    pair<sitemap_t::const_iterator,sitemap_t::const_iterator> range=m_sites.equal_range(name);

    time_t now=time(NULL);
    for (sitemap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;
    
    if (!strict && range.first!=range.second)
        return range.first->second;
        
    return NULL;
}

const EntityDescriptor* FilesystemMetadataProvider::lookup(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return lookup(temp.get(),strict);
}
