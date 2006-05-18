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
 * ContentReference.cpp
 * 
 * SAML-specific signature reference profile 
 */
 
#include "internal.h"
#include "signature/ContentReference.h"
#include "signature/SignableObject.h"

#include <xmltooling/signature/Signature.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

using namespace opensaml;
using namespace std;

class _addprefix : public binary_function<DSIGTransformC14n*,string,void> {
public:
    void operator()(DSIGTransformC14n* t, const string& s) const {
        if (s.empty())
            t->addInclusiveNamespace("#default");
        else 
            t->addInclusiveNamespace(s.c_str());
    }
};

void ContentReference::createReferences(DSIGSignature* sig)
{
    const XMLCh* id=m_signableObject.getId();
    if (!id || !*id)
        throw xmlsignature::SignatureException("Cannot create Signature reference to SAML object without an identifier."); 
    
    DSIGReference* ref=NULL;
    XMLCh* buf=new XMLCh[XMLString::stringLen(id) + 2];
    buf[0]=chPound;
    buf[1]=chNull;
    XMLString::catString(buf,id);
    try {
        ref=sig->createReference(buf);
        delete[] buf;
    }
    catch(...) {
        delete[] buf;
        throw;
    }
    ref->appendEnvelopedSignatureTransform();
    DSIGTransformC14n* c14n=ref->appendCanonicalizationTransform(CANON_C14NE_NOC);
    for_each(m_prefixes.begin(), m_prefixes.end(), bind1st(_addprefix(),c14n));
}
