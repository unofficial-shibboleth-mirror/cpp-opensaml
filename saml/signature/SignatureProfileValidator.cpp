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
 * SignatureProfileValidator.cpp
 * 
 * SAML-specific signature verification.
 */
 
#include "internal.h"
#include "exceptions.h"
#include "signature/SignableObject.h"
#include "signature/SignatureProfileValidator.h"

#include <xmltooling/logging.h>
#include <xmltooling/signature/Signature.h>

#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/dsig/DSIGTransformList.hpp>
#include <xsec/dsig/DSIGTransformEnvelope.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

SignatureProfileValidator::SignatureProfileValidator()
{
}

SignatureProfileValidator::~SignatureProfileValidator()
{
}

void SignatureProfileValidator::validate(const XMLObject* xmlObject) const
{
    const Signature* sigObj=dynamic_cast<const Signature*>(xmlObject);
    if (!sigObj)
        throw ValidationException("Validator only applies to Signature objects.");
    validateSignature(*sigObj);
}

void SignatureProfileValidator::validateSignature(const Signature& sigObj) const
{
    DSIGSignature* sig=sigObj.getXMLSignature();
    if (!sig)
        throw ValidationException("Signature does not exist yet.");

    const SignableObject* signableObj=dynamic_cast<const SignableObject*>(sigObj.getParent());
    if (!signableObj)
        throw ValidationException("Signature is not a child of a signable SAML object.");

    if (sig->getObjectLength() != 0) {
        Category::getInstance(SAML_LOGCAT ".SignatureProfileValidator").error("signature contained an embedded <Object> element");
        throw ValidationException("Invalid signature profile for SAML object.");
    }

    sig->setIdByAttributeName(false);

    bool valid=false;
    const DSIGReferenceList* refs=sig->getReferenceList();
    if (refs && refs->getSize()==1) {
        const DSIGReference* ref=refs->item(0);
        if (ref) {
            const XMLCh* URI=ref->getURI();
            const XMLCh* ID=signableObj->getXMLID();
            if (URI==nullptr || *URI==0 || (*URI==chPound && ID && !XMLString::compareString(URI+1,ID))) {
                const DSIGTransformList* tlist=ref->getTransforms();
                if (tlist->getSize() <= 2) { 
                    for (unsigned int i=0; tlist && i<tlist->getSize(); i++) {
                        const DSIGTransform* t = tlist->item(i);
                        if (dynamic_cast<const DSIGTransformEnvelope*>(t)) {
                            valid=true;
                        }
                        else if (!dynamic_cast<const DSIGTransformC14n*>(t)) {
                            Category::getInstance(SAML_LOGCAT ".SignatureProfileValidator").error("signature contained an invalid transform");
                            valid = false;
                            break;
                        }
                    }
                }

                if (valid && URI && *URI) {
                    valid = false;
                    if (sigObj.getDOM() && signableObj->getDOM()) {
                        DOMElement* signedNode = sigObj.getDOM()->getOwnerDocument()->getElementById(ID);
                        if (signedNode && signedNode->isSameNode(signableObj->getDOM())) {
                            valid = true;
                        }
                        else {
                            Category::getInstance(SAML_LOGCAT ".SignatureProfileValidator").error("signature reference does not match parent object node");
                        }
                    }
                }
            }
            else {
                Category::getInstance(SAML_LOGCAT ".SignatureProfileValidator").error("signature reference does not match parent object ID");
            }
        }
    }
    else {
        Category::getInstance(SAML_LOGCAT ".SignatureProfileValidator").error("signature contained multiple or zero references");
    }
    
    if (!valid)
        throw ValidationException("Invalid signature profile for SAML object.");
}
