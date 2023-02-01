/*
 * Copyright (c) 2019 Linaro Limited
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

#include "mcuboot_config/mcuboot_config.h"

#ifdef MCUBOOT_X509

#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include <mbedtls/x509_crt.h>

#include <flash_map_backend/flash_map_backend.h>
#include "bootutil/bootutil_log.h"

#include "bootutil/image.h"
#include "bootutil/crypto/sha256.h"
#include "bootutil/root_cert.h"
#include "bootutil/sign_key.h"

#include "image_util.h"

MCUBOOT_LOG_MODULE_DECLARE(mcuboot);

/*
 * Current support is for EC256 signatures using SHA256 hashes.  We
 * allow some amount of data to hold the certificates.
 */
#define SIG_BUF_SIZE 2048

int verify_callback(void *buf, mbedtls_x509_crt *crt, int depth,
                    uint32_t *flags)
{
    (void) buf;
    (void) crt;
    (void) depth;
    (void) flags;

    // BOOT_LOG_ERR("callback");

    return 0;
}
/*
 * Verify the integrity of the image.
 * Return non-zero if image coule not be validated/does not validate.
 */
int
bootutil_img_validate(struct enc_key_data *enc_state, int image_index,
                      struct image_header *hdr, const struct flash_area *fap,
                      uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *seed,
                      int seed_len, uint8_t *out_hash)
{
    uint32_t off;
    uint16_t len;
    uint16_t type;
    uint8_t hash[32];
    bool sha256_valid = false;
    bool cert_valid = false;
    int rc;
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE];
    mbedtls_x509_crt chain;
    mbedtls_x509_crt trust_ca;
    uint32_t flags;
    mbedtls_x509_crt_init(&chain);
    int ret = -1;

    rc = bootutil_img_hash(enc_state, image_index, hdr, fap, tmp_buf,
                           tmp_buf_sz, hash, seed, seed_len);
    if (rc) {
        ret = rc;
        goto cleanup;
    }

    if (out_hash) {
        memcpy(out_hash, hash, 32);
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
    if (rc) {
        ret = rc;
        goto cleanup;
    }

    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            ret = -1;
            goto cleanup;
        } else if (rc > 0) {
            break;
        }

        if (type == IMAGE_TLV_SHA256) {
            /*
             * Verify the SHA256 image hash.  This must always be
             * present.
             */
            if (len != sizeof(hash)) {
                ret = -1;
                goto cleanup;
            }
            rc = flash_area_read(fap, off, buf, sizeof hash);
            if (rc) {
                ret = rc;
                goto cleanup;
            }
            if (memcmp(hash, buf, sizeof(hash))) {
                BOOT_LOG_ERR("Corrupt hash");
                ret = -1;
                goto cleanup;
            }

            sha256_valid = true;
        } else if (type == IMAGE_TLV_X509) {
            if (len > sizeof (buf)) {
                ret = -1;
                goto cleanup;
            }
            rc = flash_area_read(fap, off, buf, len);
            if (rc) {
                ret = rc;
                goto cleanup;
            }
            rc =  mbedtls_x509_crt_parse_der(&chain, buf, len);
            if (rc) {
                BOOT_LOG_ERR("Parse error %d", rc);
                ret = -1;
                goto cleanup;
            }


        } else if (type == IMAGE_TLV_ECDSA256) {
            /* Finish with the root certificate. */
            mbedtls_x509_crt_init(&trust_ca);
            rc =  mbedtls_x509_crt_parse_der(&trust_ca, bootutil_root_cert,
                                            bootutil_root_cert_len);
            if (rc) {
                BOOT_LOG_ERR("Parser error: %d", rc);
                ret = -1;
                goto cleanup;
            }

            flags = 0;
            rc = mbedtls_x509_crt_verify(&chain, &trust_ca, NULL,
                                         NULL,
                                         &flags,
                                         verify_callback, NULL);
            if (rc == 0) {
            	 // validate the image signature
            	  if (len > sizeof (buf)) {
            		  	  	  	ret = -1;
            		  	  	  	goto cleanup;
            	            }
            	            rc = flash_area_read(fap, off, buf, len);
            	            if (rc) {
            	            	ret = rc;
            	            	goto cleanup;
            	            }
            	            //Go to the last cert in the chain (product cert) to validate the image signature
            	            mbedtls_x509_crt *next_cert = &chain;
            	            while(next_cert->next != 0x00)
            	            {
            	            	next_cert=next_cert->next;
            	            }
            	            //using Publick key context from last cert(product cert) to validate the image signature
            		        rc = mbedtls_pk_verify( &next_cert->pk, next_cert->private_sig_md, hash, sizeof(hash),buf,len );
            		         if(rc == 0)
            		         {
            		            cert_valid = true;
            		            ret=rc;
            		         }
            	            }

                
        } else {
            BOOT_LOG_ERR("TLV: %d", type);
        }
    }

    if (!sha256_valid) {
        ret = -1;
    	goto cleanup;
    }
    if (!cert_valid) {
        ret = -1;
    	goto cleanup;
    }
    cleanup:
	mbedtls_x509_crt_free(&chain);
	mbedtls_x509_crt_free(&trust_ca);


    return(ret);
}
#endif /* MCUBOOT_X509 */
