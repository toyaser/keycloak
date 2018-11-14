/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.jose.jwk;

import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class JWKBuilder {

    public static final String DEFAULT_PUBLIC_KEY_USE = "sig";
    public static final String DEFAULT_MESSAGE_DIGEST = "SHA-256";
    public static final String DEFAULT_CERTIFICATE_TYPE = "X.509";
    private static final Logger LOG = Logger.getLogger(JWKBuilder.class.getName());

    private String kid;

    private JWKBuilder() {
    }

    public static JWKBuilder create() {
        return new JWKBuilder();
    }

    public JWKBuilder kid(String kid) {
        this.kid = kid;
        return this;
    }

    public JWK rs256(PublicKey key, Certificate certificate) {
        RSAPublicKey rsaKey = (RSAPublicKey) key;

        RSAPublicJWK k = new RSAPublicJWK();

        String kid = this.kid != null ? this.kid : KeyUtils.createKeyId(key);
        k.setKeyId(kid);
        k.setKeyType(RSAPublicJWK.RSA);
        k.setAlgorithm(RSAPublicJWK.RS256);
        k.setPublicKeyUse(DEFAULT_PUBLIC_KEY_USE);
        k.setModulus(Base64Url.encode(toIntegerBytes(rsaKey.getModulus())));
        k.setPublicExponent(Base64Url.encode(toIntegerBytes(rsaKey.getPublicExponent())));
        k.setX509CertificateChain(generateCertificateChain(certificate));

        return k;
    }

    /**
     * Copied from org.apache.commons.codec.binary.Base64
     */
    private static byte[] toIntegerBytes(final BigInteger bigInt) {
        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }
    
    private static String[] generateCertificateChain(Certificate certificate) {
        List<String> publicKeyChain = new ArrayList<String>();
        try {
            CertPath path = CertificateFactory.getInstance(DEFAULT_CERTIFICATE_TYPE).generateCertPath(Collections.singletonList(certificate));
            
            for (Certificate c:  path.getCertificates()) {
                String encodedPublicKey =  Base64.getEncoder().encodeToString(c.getPublicKey().getEncoded());
                publicKeyChain.add(encodedPublicKey);
            }
        } catch (CertificateException ex) {
            LOG.log(Level.WARNING, "error when creating JWK x5c certificate chain.", ex);
        }
        return publicKeyChain.toArray(new String[publicKeyChain.size()]);
    }

}
