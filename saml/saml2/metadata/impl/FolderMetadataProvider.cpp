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
 * FolderMetadataProvider.cpp
 * 
 * MetadataProvider that loads all files in a directory.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <memory>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/DirectoryWalker.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {

        static const XMLCh Chaining[] =             UNICODE_LITERAL_8(C,h,a,i,n,i,n,g);
        static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
        static const XMLCh discoveryFeed[] =        UNICODE_LITERAL_13(d,i,s,c,o,v,e,r,y,F,e,e,d);
        static const XMLCh dropDOM[] =              UNICODE_LITERAL_7(d,r,o,p,D,O,M);
        static const XMLCh legacyOrgNames[] =       UNICODE_LITERAL_14(l,e,g,a,c,y,O,r,g,N,a,m,e,s);
        static const XMLCh nested[] =               UNICODE_LITERAL_6(n,e,s,t,e,d);
        static const XMLCh path[] =                 UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh precedence[] =           UNICODE_LITERAL_10(p,r,e,c,e,d,e,n,c,e);
        static const XMLCh reloadChanges[] =        UNICODE_LITERAL_13(r,e,l,o,a,d,C,h,a,n,g,e,s);
        static const XMLCh validate[] =             UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
        static const XMLCh _XML[] =                 UNICODE_LITERAL_3(X,M,L);
    
        static void FolderCallback(const char* pathname, struct stat& stat_buf, void* data) {
            // data is a pair of DOM elements, the config root and the mocked up Chaining child
            pair<const DOMElement*,DOMElement*>* p = reinterpret_cast<pair<const DOMElement*,DOMElement*>*>(data);
            auto_ptr_XMLCh entry(pathname);

            DOMElement* child = p->first->getOwnerDocument()->createElementNS(nullptr, _MetadataProvider);
            child->setAttributeNS(nullptr, _type, _XML);
            child->setAttributeNS(nullptr, path, entry.get());
            if (p->first->hasAttributeNS(nullptr, validate))
                child->setAttributeNS(nullptr, validate, p->first->getAttributeNS(nullptr, validate));
            if (p->first->hasAttributeNS(nullptr, reloadChanges))
                child->setAttributeNS(nullptr, reloadChanges, p->first->getAttributeNS(nullptr, reloadChanges));
            if (p->first->hasAttributeNS(nullptr, discoveryFeed))
                child->setAttributeNS(nullptr, discoveryFeed, p->first->getAttributeNS(nullptr, discoveryFeed));
            if (p->first->hasAttributeNS(nullptr, legacyOrgNames))
                child->setAttributeNS(nullptr, legacyOrgNames, p->first->getAttributeNS(nullptr, legacyOrgNames));
            if (p->first->hasAttributeNS(nullptr, dropDOM))
                child->setAttributeNS(nullptr, dropDOM, p->first->getAttributeNS(nullptr, dropDOM));

            DOMElement* filter = XMLHelper::getFirstChildElement(p->first);
            while (filter) {
                child->appendChild(filter->cloneNode(true));
                filter = XMLHelper::getNextSiblingElement(filter);
            }
            p->second->appendChild(child);
        }

        MetadataProvider* SAML_DLLLOCAL FolderMetadataProviderFactory(const DOMElement* const & e, bool deprecationSupport)
        {
            // The goal here is to construct a configuration for a chain of file-based providers
            // based on the content of the directory we're given.

            auto_ptr_char p(e->getAttributeNS(nullptr, path));
            if (!p.get() || !*p.get()) {
                throw MetadataException("Folder MetadataProvider missing path setting.");
            }

            string fullname, loc(p.get());
            XMLToolingConfig::getConfig().getPathResolver()->resolve(loc, PathResolver::XMLTOOLING_CFG_FILE);

            // First we build a new root element of the right type, and copy in the precedence setting.
            DOMElement* root = e->getOwnerDocument()->createElementNS(nullptr, _MetadataProvider);
            root->setAttributeNS(nullptr, _type, Chaining);
            if (e->hasAttributeNS(nullptr, precedence))
                root->setAttributeNS(nullptr, precedence, e->getAttributeNS(nullptr, precedence));

            Category& log = Category::getInstance(SAML_LOGCAT ".MetadataProvider.Folder");
            log.info("loading metadata files from folder (%s)", loc.c_str());

            DirectoryWalker walker(log, loc.c_str(), XMLHelper::getAttrBool(e, false, nested));
            pair<const DOMElement*,DOMElement*> data = make_pair(e, root);
            walker.walk(FolderCallback, &data);

            return SAMLConfig::getConfig().MetadataProviderManager.newPlugin(CHAINING_METADATA_PROVIDER, root, deprecationSupport);
        }

    };
};
