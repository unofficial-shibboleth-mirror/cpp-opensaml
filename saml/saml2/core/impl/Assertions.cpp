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
 * Assertions.cpp
 * 
 * Built-in behavior for SAML 2.0 Assertion interfaces.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/encryption/EncryptedKeyResolver.h"
#include "saml2/core/Assertions.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "saml2/metadata/MetadataCredentialContext.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/encryption/Encrypter.h>
#include <xmltooling/encryption/Decrypter.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/util/ParserPool.h>

#include <xsec/utils/XSECPlatformUtils.hpp>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace xmlencryption;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

void EncryptedElementType::encrypt(
    const EncryptableObject& xmlObject,
    const MetadataProvider& metadataProvider,
    MetadataCredentialCriteria& criteria,
    bool compact,
    const XMLCh* algorithm
    )
{
    XMLToolingConfig& conf = XMLToolingConfig::getConfig();

    // With one recipient, we let the library generate the encryption key for us.
    // Get the key encryption key to use. To make use of EncryptionMethod, we have
    // to examine each possible credential in conjunction with the algorithms we
    // support.
    criteria.setUsage(Credential::ENCRYPTION_CREDENTIAL);
    vector<const Credential*> creds;
    if (metadataProvider.resolve(creds, &criteria) == 0)
        throw EncryptionException("No peer encryption credential found.");

    const XMLCh* dataalg;
    const XMLCh* keyalg;
    const Credential* KEK = nullptr;

    for (vector<const Credential*>::const_iterator c = creds.begin(); !KEK && c != creds.end(); ++c) {
        // Try and find EncryptionMethod information surrounding the credential.
        // All we're doing if they're present is setting algorithms where possible to
        // the algorithms preferred by the credential, if we support them.
        // The problem is that if we don't support them, the only case we can detect
        // is if neither algorithm type is set *and* there's an EncryptionMethod present.
        dataalg = keyalg = nullptr;
        const MetadataCredentialContext* metaCtx = dynamic_cast<const MetadataCredentialContext*>((*c)->getCredentialContext());
        if (metaCtx) {
            const vector<EncryptionMethod*>& encMethods = metaCtx->getKeyDescriptor().getEncryptionMethods();
            for (vector<EncryptionMethod*>::const_iterator meth = encMethods.begin(); meth != encMethods.end(); ++meth) {
                if ((*meth)->getAlgorithm()) {
                    if (!dataalg && conf.isXMLAlgorithmSupported((*meth)->getAlgorithm(), XMLToolingConfig::ALGTYPE_ENCRYPT))
                        dataalg = (*meth)->getAlgorithm();
                    else if (!keyalg && conf.isXMLAlgorithmSupported((*meth)->getAlgorithm(), XMLToolingConfig::ALGTYPE_KEYENCRYPT))
                        keyalg = (*meth)->getAlgorithm();
                }
            }

            if (!dataalg && !keyalg && !encMethods.empty()) {
                // We know nothing, and something was specified that we don't support, so keep looking.
                continue;
            }
        }

        if (!keyalg && !(keyalg = Encrypter::getKeyTransportAlgorithm(*(*c), algorithm ? algorithm : dataalg))) {
            // We can't derive a supported algorithm from the credential, so it will fail later anyway.
            continue;
        }

        // Use this key.
        KEK = *c;
    }

    if (!KEK)
        throw EncryptionException("No supported peer encryption credential found.");

    // Passed in algorithm takes precedence.
    if (algorithm && *algorithm)
        dataalg = algorithm;
    if (!dataalg) {
#ifdef XSEC_OPENSSL_HAVE_AES
        dataalg = DSIGConstants::s_unicodeStrURIAES256_CBC;
#else
        dataalg = DSIGConstants::s_unicodeStrURI3DES_CBC;
#endif
    }

    Encrypter encrypter;
    Encrypter::EncryptionParams ep(dataalg, nullptr, 0, nullptr, compact);
    Encrypter::KeyEncryptionParams kep(*KEK, keyalg);
    setEncryptedData(encrypter.encryptElement(xmlObject.marshall(), ep, &kep));
}

void EncryptedElementType::encrypt(
    const EncryptableObject& xmlObject,
    const vector< pair<const MetadataProvider*, MetadataCredentialCriteria*> >& recipients,
    bool compact,
    const XMLCh* algorithm
    )
{
    // With multiple recipients, we have to generate an encryption key and then multicast it,
    // so we need to split the encryption and key wrapping steps.
    if (!algorithm || !*algorithm) {
#ifdef XSEC_OPENSSL_HAVE_AES
        algorithm = DSIGConstants::s_unicodeStrURIAES256_CBC;
#else
        algorithm = DSIGConstants::s_unicodeStrURI3DES_CBC;
#endif
    }

    // Generate a random key.
    unsigned char keyBuffer[32];
    if (XSECPlatformUtils::g_cryptoProvider->getRandom(keyBuffer,32)<32)
        throw EncryptionException("Unable to generate encryption key; was PRNG seeded?");
    Encrypter encrypter;
    Encrypter::EncryptionParams ep(algorithm, keyBuffer, 32, nullptr, compact);
    setEncryptedData(encrypter.encryptElement(xmlObject.marshall(), ep));
    getEncryptedData()->setId(SAMLConfig::getConfig().generateIdentifier());

    // Generate a uniquely named KeyInfo.
    KeyInfo* keyInfo = KeyInfoBuilder::buildKeyInfo();
    getEncryptedData()->setKeyInfo(keyInfo);
    KeyName* carriedName = KeyNameBuilder::buildKeyName();
    keyInfo->getKeyNames().push_back(carriedName);
    carriedName->setName(SAMLConfig::getConfig().generateIdentifier());

    VectorOf(EncryptedKey) keys = getEncryptedKeys();

    // Now we encrypt the key for each recipient.
    for (vector< pair<const MetadataProvider*, MetadataCredentialCriteria*> >::const_iterator r = recipients.begin(); r!=recipients.end(); ++r) {
        // Get key encryption keys to use.
        r->second->setUsage(Credential::ENCRYPTION_CREDENTIAL);
        vector<const Credential*> creds;
        if (r->first->resolve(creds, r->second) == 0) {
            auto_ptr_char name(dynamic_cast<const EntityDescriptor*>(r->second->getRole().getParent())->getEntityID());
            logging::Category::getInstance(SAML_LOGCAT ".Encryption").warn("No key encryption credentials found for (%s).", name.get());
            continue;
        }

        const XMLCh* keyalg;
        const Credential* KEK = nullptr;

        for (vector<const Credential*>::const_iterator c = creds.begin(); !KEK && c != creds.end(); ++c) {
            // Try and find EncryptionMethod information surrounding the credential.
            // All we're doing if they're present is setting algorithms where possible to
            // the algorithms preferred by the credential, if we support them.
            // The problem is that if we don't support them, the only case we can detect
            // is if neither algorithm type is set *and* there's an EncryptionMethod present.
            keyalg = nullptr;
            const MetadataCredentialContext* metaCtx = dynamic_cast<const MetadataCredentialContext*>((*c)->getCredentialContext());
            if (metaCtx) {
                const vector<EncryptionMethod*>& encMethods = metaCtx->getKeyDescriptor().getEncryptionMethods();
                for (vector<EncryptionMethod*>::const_iterator meth = encMethods.begin(); meth != encMethods.end(); ++meth) {
                    if ((*meth)->getAlgorithm()) {
                        if (!keyalg && XMLToolingConfig::getConfig().isXMLAlgorithmSupported((*meth)->getAlgorithm(), XMLToolingConfig::ALGTYPE_KEYENCRYPT))
                            keyalg = (*meth)->getAlgorithm();
                    }
                }
            }

            if (!keyalg && !(keyalg = Encrypter::getKeyTransportAlgorithm(*(*c), algorithm))) {
                // We can't derive a supported algorithm from the credential, so it will fail later anyway.
                continue;
            }

            // Use this key.
            KEK = *c;
        }

        if (!KEK) {
            auto_ptr_char name(dynamic_cast<const EntityDescriptor*>(r->second->getRole().getParent())->getEntityID());
            logging::Category::getInstance(SAML_LOGCAT ".Encryption").warn("no supported key encryption credential found for (%s).", name.get());
            continue;
        }

        // Encrypt the key and add it to the message.
        Encrypter::KeyEncryptionParams kep(
            *KEK, keyalg, dynamic_cast<const EntityDescriptor*>(r->second->getRole().getParent())->getEntityID()
            );
        EncryptedKey* encryptedKey = encrypter.encryptKey(keyBuffer, ep.m_keyBufferSize, kep, compact);
        keys.push_back(encryptedKey);
        if (keys.size() > 1) {
            // Copy details from the other key.
            encryptedKey->setCarriedKeyName(keys.front()->getCarriedKeyName()->cloneCarriedKeyName());
            encryptedKey->setReferenceList(keys.front()->getReferenceList()->cloneReferenceList());
        }
        else {
            // Attach the carried key name.
            CarriedKeyName* carried = CarriedKeyNameBuilder::buildCarriedKeyName();
            carried->setName(carriedName->getName());
            encryptedKey->setCarriedKeyName(carried);

            // Attach a back-reference to the data.
            ReferenceList* reflist = ReferenceListBuilder::buildReferenceList();
            encryptedKey->setReferenceList(reflist);
            DataReference* dataref = DataReferenceBuilder::buildDataReference();
            reflist->getDataReferences().push_back(dataref);
            XMLCh* uri = new XMLCh[XMLString::stringLen(getEncryptedData()->getId()) + 2];
            *uri = chPound;
            *(uri+1) = chNull;
            XMLString::catString(uri, getEncryptedData()->getId());
            dataref->setURI(uri);
            delete[] uri;
        }
    }
}

XMLObject* EncryptedElementType::decrypt(
    const CredentialResolver& credResolver, const XMLCh* recipient, CredentialCriteria* criteria, bool requireAuthenticatedCipher
    ) const
{
    if (!getEncryptedData())
        throw DecryptionException("No encrypted data present.");
    opensaml::EncryptedKeyResolver ekr(*this);
    Decrypter decrypter(&credResolver, criteria, &ekr, requireAuthenticatedCipher);
    DOMDocumentFragment* frag = decrypter.decryptData(*getEncryptedData(), recipient);
    if (frag->hasChildNodes() && frag->getFirstChild()==frag->getLastChild()) {
        DOMNode* plaintext=frag->getFirstChild();
        if (plaintext->getNodeType()==DOMNode::ELEMENT_NODE) {
            // Import the tree into a new Document that we can bind to the unmarshalled object.
            XercesJanitor<DOMDocument> newdoc(XMLToolingConfig::getConfig().getParser().newDocument());
            DOMElement* treecopy;
            try {
                treecopy = static_cast<DOMElement*>(newdoc->importNode(plaintext, true));
            }
            catch (XMLException& ex) {
                frag->release();
                auto_ptr_char temp(ex.getMessage());
                throw DecryptionException(
                    string("Error importing decypted DOM into new document: ") + (temp.get() ? temp.get() : "no message")
                    );
            }
            frag->release();
            newdoc->appendChild(treecopy);
            auto_ptr<XMLObject> ret(XMLObjectBuilder::buildOneFromElement(treecopy, true));
            newdoc.release();
            return ret.release();
        }
    }
    frag->release();
    throw DecryptionException("Decryption did not result in a single element.");
}
