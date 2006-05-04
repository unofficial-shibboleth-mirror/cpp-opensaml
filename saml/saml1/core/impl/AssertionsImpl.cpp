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
 * AssertionsImpl.cpp
 * 
 * Implementation classes for SAML 1.x Assertions schema
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Assertions.h"

#include <xmltooling/AbstractChildlessElement.h>
#include <xmltooling/AbstractComplexElement.h>
#include <xmltooling/AbstractElementProxy.h>
#include <xmltooling/AbstractSimpleElement.h>
#include <xmltooling/io/AbstractXMLObjectMarshaller.h>
#include <xmltooling/io/AbstractXMLObjectUnmarshaller.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/validation/AbstractValidatingXMLObject.h>

#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {
    namespace saml1 {
    
    DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,AssertionIDReference);
    DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,Audience);
    DECL_XMLOBJECTIMPL_SIMPLE(SAML_DLLLOCAL,ConfirmationMethod);
    
    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

// Builder Implementations

IMPL_XMLOBJECTBUILDER(AssertionIDReference);
IMPL_XMLOBJECTBUILDER(Audience);
IMPL_XMLOBJECTBUILDER(ConfirmationMethod);

// Unicode literals
const XMLCh AssertionIDReference::LOCAL_NAME[] =    UNICODE_LITERAL_20(A,s,s,e,r,t,i,o,n,I,D,R,e,f,e,r,e,n,c,e);
const XMLCh Audience::LOCAL_NAME[] =                UNICODE_LITERAL_8(A,u,d,i,e,n,c,e);
const XMLCh ConfirmationMethod::LOCAL_NAME[] =      UNICODE_LITERAL_18(C,o,n,f,i,r,m,a,t,i,o,n,M,e,t,h,o,d);

#define XCH(ch) chLatin_##ch
#define XNUM(d) chDigit_##d
