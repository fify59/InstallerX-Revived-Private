// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.ui.page.main.settings.preferred.lab

import com.rosan.installer.domain.settings.model.preferences.RootMode
import com.rosan.installer.domain.settings.model.preferences.SmartAuthorizerCandidate

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
    object LabImportSigningKey : LabSettingsAction
}
