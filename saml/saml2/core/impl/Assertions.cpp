/*
 *  Copyright 2001-2007 Internet2
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
#include <xmltooling/encryption/Encrypter.h>
#include <xmltooling/encryption/Decrypter.h>

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
    // With one recipient, we let the library generate the encryption key for us.
    // Get the key encryption key to use.
    criteria.setUsage(CredentialCriteria::ENCRYPTION_CREDENTIAL);
    const Credential* KEK = metadataProvider.resolve(&criteria);
    if (!KEK)
        throw EncryptionException("No key encryption credential found.");

    // Try and find EncryptionMethod information surrounding the credential.
    const MetadataCredentialContext* metaCtx = dynamic_cast<const MetadataCredentialContext*>(KEK->getCredentalContext());
    if (metaCtx) {
        const vector<EncryptionMethod*> encMethods = metaCtx->getKeyDescriptor().getEncryptionMethods();
        if (!encMethods.empty())
            algorithm = encMethods.front()->getAlgorithm();
    }

    if (!algorithm || !*algorithm)
        algorithm = DSIGConstants::s_unicodeStrURIAES256_CBC;

    Encrypter encrypter;
    Encrypter::EncryptionParams ep(algorithm, NULL, 0, NULL, compact);
    Encrypter::KeyEncryptionParams kep(*KEK);
    setEncryptedData(encrypter.encryptElement(xmlObject.getDOM(),ep,&kep));
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
    if (!algorithm || !*algorithm)
        algorithm = DSIGConstants::s_unicodeStrURIAES256_CBC;

    // Generate a random key.
    unsigned char keyBuffer[32];
    if (XSECPlatformUtils::g_cryptoProvider->getRandom(keyBuffer,32)<32)
        throw EncryptionException("Unable to generate encryption key; was PRNG seeded?");
    Encrypter encrypter;
    Encrypter::EncryptionParams ep(algorithm, keyBuffer, 32, NULL, compact);
    setEncryptedData(encrypter.encryptElement(xmlObject.getDOM(),ep));
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
        // Get key encryption key to use.
        r->second->setUsage(CredentialCriteria::ENCRYPTION_CREDENTIAL);
        const Credential* KEK = r->first->resolve(r->second);
        if (!KEK) {
            auto_ptr_char name(dynamic_cast<const EntityDescriptor*>(r->second->getRole().getParent())->getEntityID());
            logging::Category::getInstance(SAML_LOGCAT".Encryption").warn("No key encryption credential found for (%s).", name.get());
            continue;
        }

        // Encrypt the key and add it to the message.
        Encrypter::KeyEncryptionParams kep(
            *KEK, Encrypter::getKeyTransportAlgorithm(*KEK, algorithm),
            dynamic_cast<const EntityDescriptor*>(r->second->getRole().getParent())->getEntityID()
            );
        EncryptedKey* encryptedKey = encrypter.encryptKey(keyBuffer, ep.m_keyBufferSize, kep, compact);
        keys.push_back(encryptedKey);
        if (keys.size()>1) {
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

XMLObject* EncryptedElementType::decrypt(const CredentialResolver& credResolver, const XMLCh* recipient, CredentialCriteria* criteria) const
{
    if (!getEncryptedData())
        throw DecryptionException("No encrypted data present.");
    EncryptedKeyResolver ekr(*this);
    Decrypter decrypter(&credResolver, criteria, &ekr);
    DOMDocumentFragment* frag = decrypter.decryptData(*getEncryptedData(), recipient);
    if (frag->hasChildNodes() && frag->getFirstChild()==frag->getLastChild()) {
        DOMNode* plaintext=frag->getFirstChild();
        if (plaintext->getNodeType()==DOMNode::ELEMENT_NODE) {
            // Import the tree into a new Document that we can bind to the unmarshalled object.
            XercesJanitor<DOMDocument> newdoc(XMLToolingConfig::getConfig().getParser().newDocument());
            DOMElement* treecopy = static_cast<DOMElement*>(newdoc->importNode(plaintext, true));
            newdoc->appendChild(treecopy);
            auto_ptr<XMLObject> ret(XMLObjectBuilder::buildOneFromElement(treecopy, true));
            newdoc.release();
            return ret.release();
        }
    }
    frag->release();
    throw DecryptionException("Decryption did not result in a single element.");
}
