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
 * ContentReference.cpp
 * 
 * SAML-specific signature reference profile.
 */
 
#include "internal.h"
#include "signature/ContentReference.h"
#include "signature/SignableObject.h"

#include <xmltooling/signature/Signature.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGSignature.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>

using namespace opensaml;
using namespace xmltooling;
using namespace std;

void SignableObject::declareNonVisibleNamespaces() const
{
    ContentReference* cr = getSignature() ? dynamic_cast<ContentReference*>(getSignature()->getContentReference()) : nullptr;

    // Compute inclusive prefix set.
    map<xstring,xstring> decls;
    XMLHelper::getNonVisiblyUsedPrefixes(*this, decls);

    for (map<xstring,xstring>::const_iterator decl = decls.begin(); decl != decls.end(); ++decl) {

        // Pin it to the object root. An existing copy of the prefix on the root will take precedence.
        addNamespace(Namespace(decl->second.c_str(), decl->first.c_str(), true, Namespace::NonVisiblyUsed));

        // Add to content reference, if any.
        if (cr)
            cr->addInclusivePrefix(decl->first.c_str());
    }
}

ContentReference::ContentReference(const SignableObject& signableObject)
    : m_signableObject(signableObject), m_digest(nullptr), m_c14n(nullptr)
{
}

ContentReference::~ContentReference()
{
}

void ContentReference::createReferences(DSIGSignature* sig)
{
    DSIGReference* ref = nullptr;
    sig->setIdByAttributeName(false);
    const XMLCh* id=m_signableObject.getXMLID();
    if (!id || !*id) {
        ref = sig->createReference(&chNull, 
#ifdef XSEC_OPENSSL_HAVE_SHA2
            m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA256
#else
            m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA1
#endif
            );  // whole doc reference
    }
    else {
        XMLCh* buf=new XMLCh[XMLString::stringLen(id) + 2];
        auto_arrayptr<XMLCh> bufjanitor(buf);
        buf[0]=chPound;
        buf[1]=chNull;
        XMLString::catString(buf,id);
        ref=sig->createReference(buf,
#ifdef XSEC_OPENSSL_HAVE_SHA2
            m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA256
#else
            m_digest ? m_digest : DSIGConstants::s_unicodeStrURISHA1
#endif
            );
    }
    
    ref->appendEnvelopedSignatureTransform();
    DSIGTransformC14n* c14n=ref->appendCanonicalizationTransform(m_c14n ? m_c14n : DSIGConstants::s_unicodeStrURIEXC_C14N_NOC);

    if (!m_c14n || m_c14n == DSIGConstants::s_unicodeStrURIEXC_C14N_NOC || m_c14n == DSIGConstants::s_unicodeStrURIEXC_C14N_COM) {
        // Build up the string of prefixes.
        xstring prefixes;
        static const XMLCh _default[] = { chPound, chLatin_d, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t, chNull };
        for (set<xstring>::const_iterator p = m_prefixes.begin(); p != m_prefixes.end(); ++p) {
            prefixes += (p->empty() ? _default : p->c_str());
            prefixes += chSpace;
        }
        if (!prefixes.empty()) {
            prefixes.erase(prefixes.begin() + prefixes.size() - 1);
            c14n->setInclusiveNamespaces(const_cast<XMLCh*>(prefixes.c_str())); // the cast is for compatibility with old xmlsec
        }
    }
}

void ContentReference::addInclusivePrefix(const XMLCh* prefix)
{
    m_prefixes.insert(prefix ? prefix : &chNull);
}

void ContentReference::setDigestAlgorithm(const XMLCh* digest)
{
    m_digest = digest;
}

void ContentReference::setCanonicalizationMethod(const XMLCh* c14n)
{
    m_c14n = c14n;
}
