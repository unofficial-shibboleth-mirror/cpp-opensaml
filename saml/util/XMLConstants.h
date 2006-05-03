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
 * @file XMLConstants.h
 * 
 * SAML XML namespace constants 
 */

#ifndef __saml_xmlconstants_h__
#define __saml_xmlconstants_h__

#include <xmltooling/util/XMLConstants.h>

namespace opensaml {
    
    /**
     * SAML related constants.
     */
    struct SAML_API XMLConstants : public xmltooling::XMLConstants
    {
        /**  SOAP 1.1 Envelope XML namespace ("http://schemas.xmlsoap.org/soap/envelope/") */
        static const XMLCh SOAP11ENV_NS[]; 

        /**  SOAP 1.1 Envelope QName prefix ("S") */
        static const XMLCh SOAP11ENV_PREFIX[];
    
        /**  Liberty PAOS XML Namespace ("urn:liberty:paos:2003-08") */
        static const XMLCh PAOS_NS[];
        
        /**  Liberty PAOS QName prefix ("paos") */
        static const XMLCh PAOS_PREFIX[];
    
        /**  SAML 1.X Assertion XML namespace ("urn:oasis:names:tc:SAML:1.0:assertion") */
        static const XMLCh SAML1_NS[];

        /**  SAML 1.X Protocol XML namespace ("urn:oasis:names:tc:SAML:1.0:protocol") */
        static const XMLCh SAML1P_NS[];
        
        /** SAML 1.X Assertion QName prefix ("saml") */
        static const XMLCh SAML1_PREFIX[];
    
        /** SAML 1.X Protocol QName prefix ("samlp") */
        static const XMLCh SAML1P_PREFIX[];
        
        /** SAML 1.1 Protocol Enumeration constant ("urn:oasis:names:tc:SAML:1.0:protocol") */
        static const XMLCh SAML11_PROTOCOL_ENUM[];
        
        /** SAML 1.x Metadata Profile ID ("urn:oasis:names:tc:SAML:profiles:v1metadata") */
        static const XMLCh SAML1_METADATA_PROFILE[];
        
        /**  SAML 2.0 Assertion XML namespace ("urn:oasis:names:tc:SAML:2.0:assertion") */
        static const XMLCh SAML20_NS[];

        /**  SAML 2.0 Protocol XML namespace ("urn:oasis:names:tc:SAML:2.0:protocol") */
        static const XMLCh SAML20P_NS[];

        /**  SAML 2.0 Metadata XML namespace ("urn:oasis:names:tc:SAML:2.0:metadata") */
        static const XMLCh SAML20MD_NS[];

        /**  SAML 2.0 AuthnContext XML namespace ("urn:oasis:names:tc:SAML:2.0:ac") */
        static const XMLCh SAML20AC_NS[];
        
        /** SAML 2.0 Assertion QName prefix ("saml") */
        static const XMLCh SAML20_PREFIX[];
    
        /** SAML 2.0 Protocol QName prefix ("samlp") */
        static const XMLCh SAML20P_PREFIX[];

        /** SAML 2.0 Metadata QName prefix ("md") */
        static const XMLCh SAML20MD_PREFIX[];

        /** SAML 2.0 AuthnContext QName prefix ("ac") */
        static const XMLCh SAML20AC_PREFIX[];

        /** SAML 2.0 Enhanced Client/Proxy SSO Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp") */
        static const XMLCh SAML20ECP_NS[];
        
        /** SAML 2.0 Enhanced Client/Proxy SSO Profile QName prefix ("ecp") */
        static const XMLCh SAML20ECP_PREFIX[];
    
        /** SAML 2.0 DCE PAC Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE") */
        static const XMLCh SAML20DCE_NS[];
        
        /** SAML 2.0 DCE PAC Attribute Profile QName prefix ("DCE") */
        static const XMLCh SAML20DCE_PREFIX[];
    
        /** SAML 2.0 X.500 Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500") */
        static const XMLCh SAML20X500_NS[];
        
        /** SAML 2.0 X.500 Attribute Profile QName prefix ("x500") */
        static const XMLCh SAML20X500_PREFIX[];
    
        /** SAML 2.0 XACML Attribute Profile XML Namespace ("urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML") */
        static const XMLCh SAML20XACML_NS[];
        
        /** SAML 2.0 XACML Attribute Profile QName prefix ("xacmlprof") */
        static const XMLCh SAML20XACML_PREFIX[];
    };

};

#endif /* __saml_xmlconstants_h__ */
