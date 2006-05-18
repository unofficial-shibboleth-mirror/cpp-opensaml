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
 * VerifyingContext.cpp
 * 
 * SAML-specific signature verification 
 */
 
#include "internal.h"
#include "exceptions.h"
#include "signature/SignatureProfileValidator.h"

#include <xmltooling/signature/Signature.h>

#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>
#include <xsec/dsig/DSIGTransformList.hpp>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

void SignatureProfileValidator::validate(const XMLObject* xmlObject) const
{
    const Signature* sigObj=dynamic_cast<const Signature*>(xmlObject);
    if (!sigObj)
        throw ValidationException("Validator only applies to Signature objects.");
    DSIGSignature* sig=sigObj->getXMLSignature();
    if (!sig)
        throw ValidationException("Signature does not exist yet.");

    const SignableObject* signableObj=dynamic_cast<const SignableObject*>(sigObj->getParent());
    if (!signableObj)
        throw ValidationException("Signature is not a child of a signable SAML object.");
    
    bool valid=false;
    DSIGReferenceList* refs=sig->getReferenceList();
    if (refs && refs->getSize()==1) {
        DSIGReference* ref=refs->item(0);
        if (ref) {
            const XMLCh* URI=ref->getURI();
            if (URI==NULL || *URI==0 || (*URI==chPound && !XMLString::compareString(URI+1,signableObj->getId()))) {
                DSIGTransformList* tlist=ref->getTransforms();
                for (unsigned int i=0; tlist && i<tlist->getSize(); i++) {
                    if (tlist->item(i)->getTransformType()==TRANSFORM_ENVELOPED_SIGNATURE)
                        valid=true;
                    else if (tlist->item(i)->getTransformType()!=TRANSFORM_EXC_C14N &&
                             tlist->item(i)->getTransformType()!=TRANSFORM_C14N) {
                        valid=false;
                        break;
                    }
                }
            }
        }
    }
    
    if (!valid)
        throw ValidationException("Invalid signature profile for SAML object.");
}
