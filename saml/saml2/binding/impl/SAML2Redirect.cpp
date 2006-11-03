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
 * @file saml/saml2/binding/SAML2Redirect.h
 * 
 * SAML 2.0 HTTP Redirect compression functionality
 */

#include "internal.h"
#include "saml2/binding/SAML2Redirect.h"
#include "zlib/zlib.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>

using namespace log4cpp;
using namespace std;

namespace {
    extern "C" {
        voidpf saml_zalloc(void* opaque, uInt items, uInt size)
        {
            return malloc(items*size);
        }
        
        void saml_zfree(void* opaque, voidpf addr)
        {
            free(addr);
        }
    };
};

unsigned int opensaml::saml2p::inflate(char* in, unsigned int in_len, ostream& out)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("inflate");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2Redirect.zlib");

    z_stream z;
    memset(&z, 0, sizeof(z_stream));
    
    z.zalloc = saml_zalloc;
    z.zfree = saml_zfree;
    z.opaque = NULL;
    z.next_in = (Bytef*)in;
    z.avail_in = in_len;
  
    int dlen = in_len << 3;  /* guess inflated size: orig_size * 8 */
    Byte* buf = new Byte[dlen];
    memset(buf, 0, dlen);
    z.next_out = buf;
    z.avail_out = dlen;
  
    int ret = inflateInit2(&z, -15);
    if (ret != Z_OK) {
        log.error("zlib inflateInit failed with error code (%d)", ret);
        delete[] buf;
        return 0;
    }
  
    int iter = 30;
    while (--iter) {  /* Make sure we can never be caught in infinite loop */
        ret = inflate(&z, Z_SYNC_FLUSH);
        switch (ret) {
            case Z_STREAM_END:
                ret = z.next_out - buf;
                z.next_out = buf;
                while (ret--)
                    out << *(z.next_out++);
                goto done;
                
            case Z_OK:  /* avail_out should be 0 now. Time to dump the buffer. */
                ret = z.next_out - buf;
                z.next_out = buf;
                while (ret--)
                    out << *(z.next_out++);
                memset(buf, 0, dlen);
                z.next_out = buf;
                z.avail_out = dlen;
                break;
              
            default:
                delete[] buf;
                inflateEnd(&z);
                log.error("zlib inflate failed with error code (%d)", ret);
                return 0;
        }
    }
done:
    delete[] buf;
    int out_len = z.total_out;
    inflateEnd(&z);
    return out_len;
}
