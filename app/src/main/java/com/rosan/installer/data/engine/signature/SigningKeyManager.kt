// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.data.engine.signature

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.lang.reflect.Method
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Manages the APK signing key pair in Android KeyStore.
 * Generates a new key on first use, persists it for subsequent uses.
 */
object SigningKeyManager {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "installerx_apk_signing_key"
    private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
    private const val KEY_SIZE = 2048
    private const val VALIDITY_YEARS = 25

    /**
     * Gets or creates the signing key pair.
     * On first call, generates a new RSA key pair and self-signed certificate.
     * Subsequent calls return the cached key pair.
     */
    @Throws(Exception::class)
    fun getOrCreateKeyPair(context: Context): Pair<PrivateKey, X509Certificate> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateKeyPair(keyStore)
        }

        val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey to entry.certificate as X509Certificate
    }

    /**
     * Generates a new RSA key pair with a self-signed X.509 certificate.
     */
    private fun generateKeyPair(keyStore: KeyStore) {
        val startDate = Date()
        val endDate = Date(startDate.time + VALIDITY_YEARS * 365L * 24 * 60 * 60 * 1000)

        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(KEY_SIZE)
            .setCertificateSubject(X500Principal("CN=InstallerX APK Signing Key"))
            .setCertificateSerialNumber(BigInteger.ONE)
            .setRandomizedEncryptionRequired(false)

        // setCertificateValidity was deprecated in API 29 and removed in API 33
        // Use reflection to support all API levels
        try {
            val method = KeyGenParameterSpec.Builder::class.java.getDeclaredMethod(
                "setCertificateValidity",
                Date::class.java,
                Date::class.java
            )
            method.isAccessible = true
            method.invoke(builder, startDate, endDate)
        } catch (e: Exception) {
            // Fallback for API 29+ where setCertificateNotBefore/NotAfter are available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setCertificateNotBefore(startDate)
                builder.setCertificateNotAfter(endDate)
            }
        }

        val spec = builder.build()

        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, KEYSTORE_PROVIDER)
        keyPairGenerator.initialize(spec, SecureRandom())
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Exports the certificate as PEM string for debugging/sharing.
     */
    fun exportCertificatePem(context: Context): String {
        val (_, certificate) = getOrCreateKeyPair(context)
        val pem = "-----BEGIN CERTIFICATE-----\n" +
            Base64.encodeToString(certificate.encoded, Base64.DEFAULT).trim() +
            "\n-----END CERTIFICATE-----"
        return pem
    }

    /**
     * Deletes the signing key (for testing/reset).
     */
    fun deleteKey(context: Context) {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }
}
