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
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/XMLHelper.h>

#ifndef WIN32
# if defined(HAVE_SYS_TYPES_H) && defined(HAVE_DIRENT_H)
#  include <dirent.h>
#  include <sys/types.h>
#  include <sys/stat.h>
# else
#  error Unsupported directory library headers.
# endif
#endif

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
        static const XMLCh path[] =                 UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh precedence[] =           UNICODE_LITERAL_10(p,r,e,c,e,d,e,n,c,e);
        static const XMLCh reloadChanges[] =        UNICODE_LITERAL_13(r,e,l,o,a,d,C,h,a,n,g,e,s);
        static const XMLCh validate[] =             UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
        static const XMLCh _XML[] =                 UNICODE_LITERAL_3(X,M,L);
    
        MetadataProvider* SAML_DLLLOCAL FolderMetadataProviderFactory(const DOMElement* const & e)
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

#ifdef WIN32
            WIN32_FIND_DATA f;
            fullname = loc + "/*";
            HANDLE h = FindFirstFile(fullname.c_str(), &f);
            if (h == INVALID_HANDLE_VALUE) {
                if (GetLastError() != ERROR_FILE_NOT_FOUND)
                    throw MetadataException("Folder MetadataProvider unable to open directory ($1)", params(1, loc.c_str()));
                log.warn("no files found in folder (%s)", loc.c_str());
                return SAMLConfig::getConfig().MetadataProviderManager.newPlugin(CHAINING_METADATA_PROVIDER, root);
            }
            do {
                if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (strcmp(f.cFileName, ".") && strcmp(f.cFileName, ".."))
                        log.warn("nested folders not supported, skipping (%s)", f.cFileName);
                    continue;
                }
                fullname = loc + '/' + f.cFileName;
                log.info("will create metadata source from (%s)", fullname.c_str());
                auto_ptr_XMLCh entry(fullname.c_str());
#else
            DIR* d = opendir(loc.c_str());
            if (!d) {
                throw MetadataException("Folder MetadataProvider unable to open directory ($1)", params(1, loc.c_str()));
            }
            char dir_buf[sizeof(struct dirent) + PATH_MAX];
            struct dirent* ent = (struct dirent*)dir_buf;
            struct dirent* entptr = nullptr;
            while(readdir_r(d, ent, &entptr) == 0 && entptr) {
                if (!strcmp(entptr->d_name, ".") || !strcmp(entptr->d_name, ".."))
                    continue;
                fullname = loc + '/' + entptr->d_name;
                struct stat stat_buf;
                if (stat(fullname.c_str(), &stat_buf) != 0) {
                    log.warn("unable to access (%s)", entptr->d_name);
                    continue;
                }
                else if (S_ISDIR(stat_buf.st_mode)) {
                    log.warn("nested folders not supported, skipping (%s)", entptr->d_name);
                    continue;
                }
                log.info("will create metadata source from (%s)", fullname.c_str());
                auto_ptr_XMLCh entry(fullname.c_str());
#endif
                DOMElement* child = e->getOwnerDocument()->createElementNS(nullptr, _MetadataProvider);
                child->setAttributeNS(nullptr, _type, _XML);
                child->setAttributeNS(nullptr, path, entry.get());
                if (e->hasAttributeNS(nullptr, validate))
                    child->setAttributeNS(nullptr, validate, e->getAttributeNS(nullptr, validate));
                if (e->hasAttributeNS(nullptr, reloadChanges))
                    child->setAttributeNS(nullptr, reloadChanges, e->getAttributeNS(nullptr, reloadChanges));
                if (e->hasAttributeNS(nullptr, discoveryFeed))
                    child->setAttributeNS(nullptr, discoveryFeed, e->getAttributeNS(nullptr, discoveryFeed));
                if (e->hasAttributeNS(nullptr, legacyOrgNames))
                    child->setAttributeNS(nullptr, legacyOrgNames, e->getAttributeNS(nullptr, legacyOrgNames));
                if (e->hasAttributeNS(nullptr, dropDOM))
                    child->setAttributeNS(nullptr, dropDOM, e->getAttributeNS(nullptr, dropDOM));

                DOMElement* filter = XMLHelper::getFirstChildElement(e);
                while (filter) {
                    child->appendChild(filter->cloneNode(true));
                    filter = XMLHelper::getNextSiblingElement(filter);
                }
                root->appendChild(child);

#ifdef WIN32
            } while (FindNextFile(h, &f));
            FindClose(h);
#else
            }
            closedir(d);
#endif
            return SAMLConfig::getConfig().MetadataProviderManager.newPlugin(CHAINING_METADATA_PROVIDER, root);
        }

    };
};
