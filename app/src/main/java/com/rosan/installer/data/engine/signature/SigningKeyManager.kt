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
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameters
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.security.auth.x500.X500Principal

/**
 * Manages the APK signing key pair.
 * Supports auto-generated key in Android KeyStore or imported key from files.
 * Inspired by AppManagerNG's KeyStoreManager - supports alias-based keys with passwords.
 */
object SigningKeyManager {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val DEFAULT_KEY_ALIAS = "installerx_apk_signing_key"
    private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
    private const val KEY_SIZE = 2048
    private const val VALIDITY_YEARS = 25

    // In-memory storage for imported keys (since Android KeyStore doesn't support arbitrary key import)
    private var importedPrivateKey: PrivateKey? = null
    private var importedCertificate: X509Certificate? = null
    private var importedAlias: String? = null

    /**
     * Gets or creates the signing key pair.
     * On first call, generates a new RSA key pair and self-signed certificate in KeyStore.
     * Subsequent calls return the cached key pair.
     * If a custom key was imported, returns that instead.
     */
    @Throws(Exception::class)
    fun getOrCreateKeyPair(context: Context): Pair<PrivateKey, X509Certificate> {
        // Return imported key if available
        if (importedPrivateKey != null && importedCertificate != null) {
            return importedPrivateKey!! to importedCertificate!!
        }

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        if (!keyStore.containsAlias(DEFAULT_KEY_ALIAS)) {
            generateKeyPair(keyStore)
        }

        val entry = keyStore.getEntry(DEFAULT_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey to entry.certificate as X509Certificate
    }

    /**
     * Gets the signing key pair with a specific alias.
     * Returns imported key if it matches the alias, otherwise falls back to default.
     */
    @Throws(Exception::class)
    fun getKeyPair(context: Context, alias: String): Pair<PrivateKey, X509Certificate> {
        // Return imported key if it matches the alias
        if (importedPrivateKey != null && importedCertificate != null && importedAlias == alias) {
            return importedPrivateKey!! to importedCertificate!!
        }

        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        if (!keyStore.containsAlias(alias)) {
            if (alias == DEFAULT_KEY_ALIAS) {
                generateKeyPair(keyStore)
            } else {
                throw KeyStoreException("Alias $alias not found in KeyStore")
            }
        }

        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey to entry.certificate as X509Certificate
    }

    /**
     * Imports a private key and certificate from PEM/PKCS#8 files with optional password.
     * Supports:
     * - PKCS#8 private key (.pk8, .pem, .key) - optionally encrypted with password
     * - X.509 certificate (.pem, .crt, .cer, .der)
     * - Combined PEM file with both private key and certificate
     *
     * @param context Application context
     * @param privateKeyFile File containing the private key
     * @param certificateFile File containing the certificate (optional if combined in privateKeyFile)
     * @param alias Alias to store the key under (default: installerx_apk_signing_key)
     * @param password Password for encrypted PKCS#8 private key (optional)
     */
    @Throws(Exception::class)
    fun importKeyPair(
        context: Context,
        privateKeyFile: File,
        certificateFile: File? = null,
        alias: String = DEFAULT_KEY_ALIAS,
        password: String? = null,
    ): Pair<PrivateKey, X509Certificate> {
        // Read private key
        val privateKey = readPrivateKey(privateKeyFile, password)

        // Read certificate
        val certificate = certificateFile?.let { readCertificate(it) }
            ?: readCertificateFromPrivateKey(privateKeyFile, privateKey)
            ?: throw IllegalArgumentException("Certificate file is required. Please provide a certificate file (.pem, .crt, .cer) or use a PKCS#12 file.")

        // Store in memory
        importedPrivateKey = privateKey
        importedCertificate = certificate
        importedAlias = alias

        return privateKey to certificate
    }

    /**
     * Imports a key pair from a PKCS#12 keystore file (.p12, .pfx)
     * Supports password-protected PKCS#12 files with multiple entries.
     * Uses the first key entry found.
     *
     * @param context Application context
     * @param pkcs12File File containing the PKCS#12 keystore
     * @param password Password for the PKCS#12 file
     * @param alias Alias to store the key under (default: installerx_apk_signing_key)
     */
    @Throws(Exception::class)
    fun importFromPkcs12(
        context: Context,
        pkcs12File: File,
        password: String,
        alias: String = DEFAULT_KEY_ALIAS,
    ): Pair<PrivateKey, X509Certificate> {
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
            val pkcs12Alias = aliases.nextElement()
            if (pkcs12Store.isKeyEntry(pkcs12Alias)) {
                privateKey = pkcs12Store.getKey(pkcs12Alias, password.toCharArray()) as PrivateKey?
                val certChain = pkcs12Store.getCertificateChain(pkcs12Alias)
                if (certChain.isNotEmpty()) {
                    certificate = certChain[0] as X509Certificate
                }
                break
            }
        }

        if (privateKey == null || certificate == null) {
            throw IllegalArgumentException("No valid key entry found in PKCS#12 file")
        }

        // Store in memory with specified alias
        importedPrivateKey = privateKey
        importedCertificate = certificate
        importedAlias = alias

        return privateKey to certificate
    }

    private fun readPrivateKey(file: File, password: String?): PrivateKey {
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

        val keyFactory = KeyFactory.getInstance("RSA")

        // Try to read as encrypted PKCS#8 if password provided
        if (password != null && password.isNotEmpty()) {
            try {
                // Use reflection to access EncryptedPrivateKeyInfo without direct import
                val encryptedPkcs8Class = Class.forName("java.security.spec.EncryptedPrivateKeyInfo")
                val constructor = encryptedPkcs8Class.getConstructor(ByteArray::class.java)
                val pkcs8Spec = constructor.newInstance(decoded)
                val algName = encryptedPkcs8Class.getMethod("getAlgName").invoke(pkcs8Spec) as String
                val cipher = Cipher.getInstance(algName)
                val key = SecretKeyFactory.getInstance(algName)
                    .generateSecret(PBEKeySpec(password.toCharArray()))
                val algParamsMethod = encryptedPkcs8Class.getMethod("getAlgParameters")
                val algParams = algParamsMethod.invoke(pkcs8Spec) as AlgorithmParameters
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeyFactory.getInstance(algName)
                        .generateSecret(PBEKeySpec(password.toCharArray())),
                    algParams,
                )
                val encryptedData = encryptedPkcs8Class.getMethod("getEncryptedData").invoke(pkcs8Spec) as ByteArray
                val decrypted = cipher.doFinal(encryptedData)
                val keySpec = PKCS8EncodedKeySpec(decrypted)
                return keyFactory.generatePrivate(keySpec)
            } catch (e: Exception) {
                // Fall through to try unencrypted
            }
        }

        // Try as unencrypted PKCS#8
        val keySpec = PKCS8EncodedKeySpec(decoded)
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

    /**
     * Clears any imported key, reverting to auto-generated KeyStore key.
     */
    fun clearImportedKey() {
        importedPrivateKey = null
        importedCertificate = null
        importedAlias = null
    }

    /**
     * Checks if a custom key has been imported.
     */
    fun hasCustomKey(): Boolean = importedPrivateKey != null && importedCertificate != null

    /**
     * Gets the alias of the currently imported key.
     */
    fun getImportedAlias(): String? = importedAlias

    /**
     * Generates a new RSA key pair with a self-signed X.509 certificate in Android KeyStore.
     */
    private fun generateKeyPair(keyStore: KeyStore) {
        val startDate = Date()
        val endDate = Date(startDate.time + VALIDITY_YEARS * 365L * 24 * 60 * 60 * 1000)

        val builder = KeyGenParameterSpec.Builder(DEFAULT_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
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
     * Deletes the signing key from KeyStore (for testing/reset).
     */
    fun deleteKey(context: Context) {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(DEFAULT_KEY_ALIAS)) {
            keyStore.deleteEntry(DEFAULT_KEY_ALIAS)
        }
        // Also clear imported key
        clearImportedKey()
    }
}
