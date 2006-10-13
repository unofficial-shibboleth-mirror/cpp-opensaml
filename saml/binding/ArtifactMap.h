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
 * @file saml/binding/ArtifactMap.h
 * 
 * Helper class for SAMLArtifact mapping and retrieval.
 */

#ifndef __saml_artmap_h__
#define __saml_artmap_h__

#include <saml/base.h>
#include <xmltooling/XMLObject.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/Threads.h>

namespace opensaml {

    class SAML_API SAMLArtifact;
    class SAML_DLLLOCAL ArtifactMappings;
    
    /**
     * Helper class for SAMLArtifact mapping and retrieval.
     */
    class SAML_API ArtifactMap
    {
        MAKE_NONCOPYABLE(ArtifactMap);
    public:
        
        /**
         * Creates a map on top of a particular storage service context, or in-memory.
         * 
         * @param storage       pointer to a StorageService, or NULL to keep map in memory
         * @param context       optional label for storage context
         * @param artifactTTL   time to live value, determines how long artifact remains valid
         */
        ArtifactMap(xmltooling::StorageService* storage=NULL, const char* context=NULL, int artifactTTL=180);

        virtual ~ArtifactMap();
        
        /**
         * Associates XML content with an artifact and optionally a specific relying party.
         * Specifying no relying party means that the first attempt to resolve the artifact
         * will succeed. The XML content cannot have a parent object, and any existing references
         * to the content will be invalidated.
         * 
         * @param content       the XML content to map to an artifact
         * @param artifact      the artifact representing the XML content
         * @param relyingParty  entityID of the party authorized to resolve the artifact
         * @return the generated artifact
         */
        virtual void storeContent(xmltooling::XMLObject* content, const SAMLArtifact* artifact, const char* relyingParty=NULL);
        
        /**
         * Retrieves the XML content represented by the artifact. The identity of the
         * relying party can be supplied, if known. If the wrong party tries to resolve
         * an artifact, an exception will be thrown and the mapping will be removed.
         * The caller is responsible for freeing the XML content returned.
         * 
         * @param artifact      the artifact representing the XML content
         * @param relyingParty  entityID of the party trying to resolve the artifact
         * @return the XML content
         */
        virtual xmltooling::XMLObject* retrieveContent(const SAMLArtifact* artifact, const char* relyingParty=NULL);

    private:
        xmltooling::StorageService* m_storage;
        std::string m_context;
        ArtifactMappings* m_mappings;
        int m_artifactTTL;
    };
};

#endif /* __saml_artmap_h__ */
