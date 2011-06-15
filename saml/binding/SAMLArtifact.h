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
 * @file saml/binding/SAMLArtifact.h
 * 
 * Base class for SAML 1.x and 2.0 artifacts.
 */

#ifndef __saml_artifact_h__
#define __saml_artifact_h__

#include <saml/base.h>

#include <string>
#include <xmltooling/exceptions.h>

namespace opensaml {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for SAML 1.x and 2.0 artifacts.
     */
    class SAML_API SAMLArtifact
    {
        SAMLArtifact& operator=(const SAMLArtifact& src);
    public:
        virtual ~SAMLArtifact();

        /**
         * Returns artifact encoded into null-terminated base64 for transmission.
         */
        virtual std::string encode() const;
        
        /**
         * Builds a duplicate, independent artifact of the same type.
         * 
         * @return the new artifact
         */
        virtual SAMLArtifact* clone() const=0;
        
        /**
         * Returns all of the raw binary data that makes up the artifact.
         * The result is NOT null-terminated.
         * 
         * @return the binary artifact data
         */
        virtual std::string getBytes() const;

        /**
         * Returns the binary type code of the artifact.
         * The result MAY contain embedded null characters.
         * 
         * @return the binary type code
         */
        virtual std::string getTypeCode() const;
        
        /**
         * Returns the binary artifact data following the type code.
         * The result MAY contain embedded null characters.
         * 
         * @return the binary artifact data
         */
        virtual std::string getRemainingArtifact() const;
        
        /**
         * Returns a string that identifies the source of the artifact.
         * The exact form this takes depends on the type but should match
         * the syntax needed for metadata lookup.
         * 
         * @return null-terminated source string
         */
        virtual std::string getSource() const=0;
        
        /**
         * Returns the binary data that references the message (2.0) or assertion (1.x)
         * The exact form this takes depends on the type.
         * The result MAY contain embedded null characters.
         * 
         * @return the binary reference data
         */
        virtual std::string getMessageHandle() const=0;

        /** Length of type code */            
        static const unsigned int TYPECODE_LENGTH;

        /**
         * Parses a base64-encoded null-terminated string into an artifact,
         * if the type is known.
         * 
         * @param s base64-encoded artifact
         * @return the decoded artifact
         */
        static SAMLArtifact* parse(const char* s);
        
        /**
         * Parses a base64-encoded null-terminated string into an artifact,
         * if the type is known.
         * 
         * @param s base64-encoded artifact
         * @return the decoded artifact
         */
        static SAMLArtifact* parse(const XMLCh* s);

        /**
         * Converts binary data to hex notation.
         * 
         * @param s the bytes to convert
         * @return  the data in hex form, 2 characters per byte
         */
        static std::string toHex(const std::string& s);
        
    protected:
        SAMLArtifact();

        /**
         * Decodes a base64-encoded artifact into its raw form.
         * 
         * @param s NULL-terminated base64-encoded string 
         */        
        SAMLArtifact(const char* s);

        SAMLArtifact(const SAMLArtifact& src);
        
        /** Raw binary data that makes up an artifact. */
        std::string m_raw;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    DECL_XMLTOOLING_EXCEPTION(ArtifactException,SAML_EXCEPTIONAPI(SAML_API),opensaml,xmltooling::XMLToolingException,Exceptions related to artifact parsing);
    
    /**
     * Registers SAMLArtifact subclasses into the runtime.
     */
    void SAML_API registerSAMLArtifacts();
};

#endif /* __saml_artifact_h__ */
