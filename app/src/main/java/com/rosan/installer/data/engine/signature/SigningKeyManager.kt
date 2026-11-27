// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.data.engine.signature

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.io.FileInputStream
import java.lang.reflect.Method
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Manages the APK signing key pair in Android KeyStore.
 * Generates a new key on first use, or imports an existing key.
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
     * Imports a private key and certificate from PEM/PKCS#8 files.
     * Supports:
     * - PKCS#8 private key (.pk8, .pem, .key)
     * - X.509 certificate (.pem, .crt, .cer, .der)
     * - Combined PEM file with both private key and certificate
     */
    @Throws(Exception::class)
    fun importKeyPair(
        context: Context,
        privateKeyFile: File,
        certificateFile: File? = null
    ): Pair<PrivateKey, X509Certificate> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        // Delete existing key if present
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        // Read private key
        val privateKey = readPrivateKey(privateKeyFile)

        // Read certificate
        val certificate = certificateFile?.let { readCertificate(it) }
            ?: readCertificateFromPrivateKey(privateKeyFile, privateKey)
            ?: generateSelfSignedCertificate(privateKey)

        // Store in KeyStore
        storeKeyPair(keyStore, privateKey, certificate)

        return privateKey to certificate
    }

    /**
     * Imports a key pair from a PKCS#12 keystore file (.p12, .pfx)
     */
    @Throws(Exception::class)
    fun importFromPkcs12(
        context: Context,
        pkcs12File: File,
        password: String
    ): Pair<PrivateKey, X509Certificate> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        // Delete existing key if present
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        // Load PKCS#12
        val pkcs12Store = KeyStore.getInstance("PKCS12")
        FileInputStream(pkcs12File).use { input ->
            pkcs12Store.load(input, password.toCharArray())
        }

        // Find the first private key entry
        val aliases = pkcs12Store.aliases()
        var privateKey: PrivateKey? = null
        var certificate: X509Certificate? = null

        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (pkcs12Store.isKeyEntry(alias)) {
                privateKey = pkcs12Store.getKey(alias, password.toCharArray()) as PrivateKey?
                val certChain = pkcs12Store.getCertificateChain(alias)
                if (certChain.isNotEmpty()) {
                    certificate = certChain[0] as X509Certificate
                }
                break
            }
        }

        if (privateKey == null || certificate == null) {
            throw IllegalArgumentException("No valid key entry found in PKCS#12 file")
        }

        // Store in Android KeyStore
        storeKeyPair(keyStore, privateKey, certificate)

        return privateKey to certificate
    }

    private fun readPrivateKey(file: File): PrivateKey {
        val bytes = file.readBytes()
        val content = String(bytes).trim()

        // Handle PEM format
        val pemContent = if (content.startsWith("-----BEGIN")) {
            content.lines()
                .filter { !it.startsWith("-----") }
                .joinToString("")
        } else {
            content
        }

        val decoded = Base64.decode(pemContent, Base64.DEFAULT)
        val keySpec = PKCS8EncodedKeySpec(decoded)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }

    private fun readCertificate(file: File): X509Certificate {
        val input = FileInputStream(file)
        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(input) as X509Certificate
        } finally {
            input.close()
        }
    }

    private fun readCertificateFromPrivateKey(file: File, privateKey: PrivateKey): X509Certificate? {
        // Try to extract certificate from combined PEM file
        val content = String(file.readBytes())
        val certPattern = "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----".toRegex()
        val match = certPattern.find(content)
        if (match != null) {
            val certPem = match.value
            val certBytes = certPem.lines()
                .filter { !it.startsWith("-----") }
                .joinToString("")
                .let { Base64.decode(it, Base64.DEFAULT) }
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(java.io.ByteArrayInputStream(certBytes)) as X509Certificate
        }
        return null
    }

    private fun generateSelfSignedCertificate(privateKey: PrivateKey): X509Certificate {
        // This is a fallback - in practice we should require a certificate
        throw IllegalArgumentException("Certificate file is required. Please provide a certificate file (.pem, .crt, .cer) or use a PKCS#12 file.")
    }

    private fun storeKeyPair(
        keyStore: KeyStore,
        privateKey: PrivateKey,
        certificate: X509Certificate
    ) {
        val startDate = Date()
        val endDate = Date(startDate.time + VALIDITY_YEARS * 365L * 24 * 60 * 60 * 1000)

        // We need to create a certificate with our desired validity
        // Since we can't modify the imported certificate, we store it as-is
        // and use a KeyProtection for signing
        val protection = KeyStore.ProtectionParameter.Builder()
            .build()

        // Android KeyStore doesn't allow direct import of existing key pairs
        // We need to use a workaround: generate a new key and replace it
        // Actually, for Android KeyStore, we can't directly import arbitrary keys
        // The proper approach is to use the imported key for signing directly
        // but that requires keeping the key in memory

        // For now, store as a PrivateKeyEntry with the certificate
        val entry = KeyStore.PrivateKeyEntry(
            arrayOf(certificate),
            privateKey,
            KeyStore.ProtectionParameter.Builder().build()
        )
        keyStore.setEntry(KEY_ALIAS, entry, protection)
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
                Date::class.java,
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

    /**
     * Checks if a custom key has been imported (vs auto-generated).
     * Currently we can't easily distinguish, so this returns false.
     * Could be enhanced by storing a preference flag.
     */
    fun hasCustomKey(context: Context): Boolean {
        // Could check if key was imported by checking a flag in preferences
        return false
    }
}
