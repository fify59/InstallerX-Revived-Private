// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.data.engine.signature

import android.content.Context
import android.os.Build
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.IOException
import java.security.PrivateKey
import java.security.SignatureException
import java.security.cert.X509Certificate

/**
 * Configuration for APK signature schemes.
 */
data class SigSchemes(
    val v1: Boolean = true,
    val v2: Boolean = true,
    val v3: Boolean = true,
    val v4: Boolean = false,
) {
    companion object {
        val DEFAULT = SigSchemes()
        val ALL_ENABLED = SigSchemes(v1 = true, v2 = true, v3 = true, v4 = true)
        val MINIMAL = SigSchemes(v1 = true, v2 = true, v3 = false, v4 = false)
    }
}

/**
 * Result of APK signing operation.
 */
data class SignResult(
    val signedApk: File,
    val idsig: File? = null,
)

/**
 * Signs APK files using Android's ApkSigner (apksig library).
 * Supports v1 (JAR), v2 (APK Signature Scheme v2), v3, and v4 signing.
 */
class ApkSigner(
    private val privateKey: PrivateKey,
    private val certificate: X509Certificate,
    private val schemes: SigSchemes = SigSchemes.DEFAULT,
    private val zipAlign: Boolean = true,
) {
    private const val TAG = "ApkSigner"

    /**
     * Signs an APK file.
     * @param inputApk The input APK file to sign
     * @param outputApk The output signed APK file
     * @return SignResult containing the signed APK and optional v4 .idsig file
     */
    @Throws(IOException::class, SignatureException::class)
    fun sign(inputApk: File, outputApk: File): SignResult {
        val signerConfig = ApkSigner.SignerConfig.Builder("CERT", privateKey, listOf(certificate)).build()
        val builder = ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(inputApk)
            .setOutputApk(outputApk)
            .setCreatedBy("InstallerX")
            .setAlignFileSize(zipAlign)
            .setV1SigningEnabled(schemes.v1)
            .setV2SigningEnabled(schemes.v2)
            .setV3SigningEnabled(schemes.v3)

        var idsigFile: File? = null
        if (schemes.v4) {
            idsigFile = File(outputApk.parentFile, "${outputApk.name}.idsig")
            builder.setV4SigningEnabled(true).setV4SignatureOutputFile(idsigFile!!)
        }

        val apkSigner = ApkSigner(builder.build())
        apkSigner.sign()

        // Verify the signature
        if (!verify(outputApk, idsigFile)) {
            throw SignatureException("Signature verification failed after signing")
        }

        return SignResult(outputApk, idsigFile)
    }

    /**
     * Verifies an APK signature.
     */
    fun verify(apk: File, idsig: File?): Boolean {
        val builder = ApkVerifier.Builder(apk).setMaxCheckedPlatformVersion(Build.VERSION.SDK_INT)
        if (schemes.v4 && idsig != null) {
            builder.setV4SignatureFile(idsig)
        }
        val verifier = builder.build()
        try {
            val result = verifier.verify()
            return result.isVerified
        } catch (e: Exception) {
            return false
        }
    }
}

/**
 * High-level helper for signing APKs during installation.
 * Handles key management and caching of signed APKs.
 */
class InstallApkSigner(
    private val context: Context,
) {
    private var cachedSigner: ApkSigner? = null
    private var cachedSchemes: SigSchemes? = null
    private var cachedZipAlign: Boolean = true

    /**
     * Initializes the signer with the given configuration.
     * Must be called before signing.
     */
    @Throws(Exception::class)
    fun initialize(schemes: SigSchemes, zipAlign: Boolean) {
        if (cachedSigner != null && cachedSchemes == schemes && cachedZipAlign == zipAlign) {
            return // Already initialized with same config
        }
        val (privateKey, certificate) = SigningKeyManager.getOrCreateKeyPair(context)
        cachedSigner = ApkSigner(privateKey, certificate, schemes, zipAlign)
        cachedSchemes = schemes
        cachedZipAlign = zipAlign
    }

    /**
     * Signs an APK if signing is enabled, otherwise returns the original file.
     * The signed APK is cached in the app's cache directory.
     */
    @Throws(IOException::class, SignatureException::class)
    fun maybeSignApk(inputApk: File, enableSigning: Boolean): File {
        if (!enableSigning || cachedSigner == null) {
            return inputApk
        }

        val cacheDir = context.cacheDir
        val outputApk = File(cacheDir, "signed_${inputApk.name}")

        // Clean up any existing cached file
        if (outputApk.exists()) {
            outputApk.delete()
        }

        val result = cachedSigner!!.sign(inputApk, outputApk)
        return result.signedApk
    }

    /**
     * Gets the certificate PEM for display/verification.
     */
    fun getCertificatePem(): String = SigningKeyManager.exportCertificatePem(context)
}
