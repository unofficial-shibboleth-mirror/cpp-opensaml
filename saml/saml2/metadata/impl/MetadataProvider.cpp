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
 * MetadataProvider.cpp
 * 
 * Registration of factories for built-in providers
 */

#include "internal.h"
#include "saml2/metadata/MetadataProvider.h"

using namespace xmltooling;

namespace opensaml {
    namespace saml2md {
        SAML_DLLLOCAL PluginManager<MetadataProvider,const DOMElement*>::Factory FilesystemMetadataProviderFactory; 
    };
};

void SAML_API opensaml::saml2md::registerMetadataProviders()
{
    SAMLConfig::getConfig().MetadataProviderManager.registerFactory(FILESYSTEM_METADATA_PROVIDER, FilesystemMetadataProviderFactory);
}
