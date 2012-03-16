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
 * ObservableMetadataProvider.cpp
 * 
 * A metadata provider that notifies interested parties of changes.
 */

#include "internal.h"
#include "saml2/metadata/ObservableMetadataProvider.h"

#include <boost/bind.hpp>
#include <xmltooling/util/Threads.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace boost;
using namespace std;

ObservableMetadataProvider::ObservableMetadataProvider(const xercesc::DOMElement* e)
    : MetadataProvider(e), m_observerLock(Mutex::create())
{
}

ObservableMetadataProvider::~ObservableMetadataProvider()
{
}

void ObservableMetadataProvider::emitChangeEvent() const
{
    Lock lock(m_observerLock);
    for_each(m_observers.begin(), m_observers.end(), boost::bind(&Observer::onEvent, _1, boost::cref(*this)));
}

void ObservableMetadataProvider::emitChangeEvent(const EntityDescriptor& entity) const
{
    Lock lock(m_observerLock);
    for_each(m_observers.begin(), m_observers.end(), boost::bind(&Observer::onEvent, _1, boost::cref(*this), boost::cref(entity)));
}

void ObservableMetadataProvider::addObserver(const Observer* newObserver) const
{
    Lock lock(m_observerLock);
    m_observers.push_back(newObserver);
}

const ObservableMetadataProvider::Observer* ObservableMetadataProvider::removeObserver(const Observer* oldObserver) const
{
    Lock lock(m_observerLock);
    vector<const Observer*>::iterator i = find(m_observers.begin(), m_observers.end(), oldObserver);
    if (i != m_observers.end()) {
        m_observers.erase(i);
        return oldObserver;
    }
    return nullptr;
}

ObservableMetadataProvider::Observer::Observer()
{
}

ObservableMetadataProvider::Observer::~Observer()
{
}

void ObservableMetadataProvider::Observer::onEvent(const ObservableMetadataProvider& provider, const EntityDescriptor&) const
{ 
    onEvent(provider);
}
