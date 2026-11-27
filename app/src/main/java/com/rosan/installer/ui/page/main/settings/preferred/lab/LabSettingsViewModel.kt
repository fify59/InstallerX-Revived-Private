// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.ui.page.main.settings.preferred.lab

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.rosan.installer.data.engine.signature.SigningKeyManager
import com.rosan.installer.domain.settings.model.preferences.SmartAuthorizerPreferences
import com.rosan.installer.domain.settings.repository.AppSettingsRepository
import com.rosan.installer.domain.settings.repository.BooleanSetting
import com.rosan.installer.domain.settings.repository.StringSetting
import com.rosan.installer.domain.settings.usecase.settings.UpdateSettingUseCase
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.File
import timber.log.Timber

class LabSettingsViewModel(
    appSettingsRepo: AppSettingsRepository,
    private val updateSetting: UpdateSettingUseCase,
    private val context: Context,
) : ViewModel() {

    val state: StateFlow<LabSettingsState> = appSettingsRepo.preferencesFlow.map { prefs ->
        LabSettingsState(
            labRootEnableModuleFlash = prefs.labRootEnableModuleFlash,
            labRootShowModuleArt = prefs.labRootShowModuleArt,
            labRootMode = prefs.labRootMode,
            labAllowInstallWithoutUserAction = prefs.labInstallWithoutUserAction,
            labRespectPlatformInstallPolicy = prefs.labRespectPlatformInstallPolicy,
            labShizukuNonAdbInstall = prefs.labShizukuNonAdbInstall,
            labEnableAbiOverride = prefs.labEnableAbiOverride,
            labTryDifferentArchitecture = prefs.labTryDifferentArchitecture,
            tryMultipleAuthorizersOnInstall = prefs.tryMultipleAuthorizersOnInstall,
            smartAuthorizerCandidates = prefs.smartAuthorizerCandidates,
            // APK Signing settings
            labEnableApkSigning = prefs.labEnableApkSigning,
            labSigningV1Scheme = prefs.labSigningV1Scheme,
            labSigningV2Scheme = prefs.labSigningV2Scheme,
            labSigningV3Scheme = prefs.labSigningV3Scheme,
            labSigningV4Scheme = prefs.labSigningV4Scheme,
            labSigningZipAlign = prefs.labSigningZipAlign,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = LabSettingsState(),
    )

    fun dispatch(action: LabSettingsAction) {
        when (action) {
            is LabSettingsAction.LabChangeRootModuleFlash -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabEnableModuleFlash,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeRootShowModuleArt -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabModuleFlashShowArt,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeRootImplementation -> viewModelScope.launch {
                updateSetting(
                    StringSetting.LabRootImplementation,
                    action.implementation.name,
                )
            }

            is LabSettingsAction.LabChangeAllowInstallWithoutUserAction -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabInstallWithoutUserAction,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeRespectPlatformInstallPolicy -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabRespectPlatformInstallPolicy,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeShizukuNonAdbInstall -> viewModelScope.launch {
                updateSetting(BooleanSetting.LabShizukuNonAdbInstall, action.enable)
            }

            is LabSettingsAction.LabChangeEnableAbiOverride -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabEnableAbiOverride,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeTryDifferentArchitecture -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabTryDifferentArchitecture,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeTryMultipleAuthorizersOnInstall -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.TryMultipleAuthorizersOnInstall,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSmartAuthorizerCandidates -> viewModelScope.launch {
                updateSetting(
                    StringSetting.SmartAuthorizerCandidates,
                    SmartAuthorizerPreferences.encode(action.candidates),
                )
            }

            // APK Signing actions
            is LabSettingsAction.LabChangeEnableApkSigning -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabEnableApkSigning,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSigningV1Scheme -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabSigningV1Scheme,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSigningV2Scheme -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabSigningV2Scheme,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSigningV3Scheme -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabSigningV3Scheme,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSigningV4Scheme -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabSigningV4Scheme,
                    action.enable,
                )
            }

            is LabSettingsAction.LabChangeSigningZipAlign -> viewModelScope.launch {
                updateSetting(
                    BooleanSetting.LabSigningZipAlign,
                    action.enable,
                )
            }

            is LabSettingsAction.LabImportSigningKey -> viewModelScope.launch {
                try {
                    SigningKeyManager.importKeyPair(
                        context,
                        action.privateKeyFile,
                        action.certificateFile
                    )
                    context.toast(R.string.lab_signing_key_imported_success)
                } catch (e: Exception) {
                    Timber.e(e, "Failed to import signing key")
                    context.toast(R.string.lab_signing_key_import_failed, e.message ?: "")
                }
            }

            is LabSettingsAction.LabImportSigningKeyPicker -> {
                // This action triggers the file picker in the UI
            }
        }
    }
}
