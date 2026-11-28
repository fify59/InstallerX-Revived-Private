// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.ui.page.main.settings.preferred.lab

import com.rosan.installer.domain.settings.model.preferences.RootMode
import com.rosan.installer.domain.settings.model.preferences.SmartAuthorizerCandidate
import java.io.File

sealed interface LabSettingsAction {
    data class LabChangeRootModuleFlash(val enable: Boolean) : LabSettingsAction
    data class LabChangeRootShowModuleArt(val enable: Boolean) : LabSettingsAction
    data class LabChangeRootImplementation(val implementation: RootMode) : LabSettingsAction
    data class LabChangeAllowInstallWithoutUserAction(val enable: Boolean) : LabSettingsAction
    data class LabChangeRespectPlatformInstallPolicy(val enable: Boolean) : LabSettingsAction
    data class LabChangeShizukuNonAdbInstall(val enable: Boolean) : LabSettingsAction
    data class LabChangeEnableAbiOverride(val enable: Boolean) : LabSettingsAction
    data class LabChangeTryDifferentArchitecture(val enable: Boolean) : LabSettingsAction
    data class LabChangeTryMultipleAuthorizersOnInstall(val enable: Boolean) : LabSettingsAction
    data class LabChangeSmartAuthorizerCandidates(val candidates: List<SmartAuthorizerCandidate>) : LabSettingsAction

    // APK Signing actions
    data class LabChangeEnableApkSigning(val enable: Boolean) : LabSettingsAction
    data class LabChangeSigningV1Scheme(val enable: Boolean) : LabSettingsAction
    data class LabChangeSigningV2Scheme(val enable: Boolean) : LabSettingsAction
    data class LabChangeSigningV3Scheme(val enable: Boolean) : LabSettingsAction
    data class LabChangeSigningV4Scheme(val enable: Boolean) : LabSettingsAction
    data class LabChangeSigningZipAlign(val enable: Boolean) : LabSettingsAction
    data class LabImportSigningKey(
        val privateKeyFile: File,
        val certificateFile: File,
        val alias: String = "installerx_apk_signing_key",
        val password: String? = null,
    ) : LabSettingsAction
    data class LabImportPkcs12(
        val pkcs12File: File,
        val password: String,
        val alias: String = "installerx_apk_signing_key",
    ) : LabSettingsAction
    
    // AppManagerNG-style keystore import (JKS, BKS, PKCS12)
    data class LabImportKeyStore(
        val keyStoreFile: File,
        val keyStorePassword: String,
        val keyType: Int, // 0=JKS, 1=PKCS12, 2=BKS, 3=PK8/PEM
        val alias: String? = null,
        val keyPassword: String? = null,
    ) : LabSettingsAction
    
    object LabClearImportedKey : LabSettingsAction
}
