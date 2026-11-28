// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2025-2026 InstallerX Revived contributors
package com.rosan.installer.ui.page.main.settings.preferred.lab

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding

import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material.MenuItem





import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults


import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rosan.installer.R
import com.rosan.installer.data.engine.signature.SigningKeyManager
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider

@Composable
fun KeyStoreImportDialog(
    onDismiss: () -> Unit,
    onTypeChange: (Int) -> Unit,
    onFileClick: () -> Unit,
    onConfirm: () -> Unit,
    keyStoreType: Int,
    keyStorePassword: String,
    onPasswordChange: (String) -> Unit,
    onFileSelected: Boolean,
    stringResource: (Int) -> String,
) {
    val keyTypes = listOf(
        stringResource(R.string.lab_java_keystore),
        stringResource(R.string.lab_pkcs12_keystore),
        stringResource(R.string.lab_bouncy_castle_keystore),
        stringResource(R.string.lab_pem_and_pk8),
    )
    var expanded by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.lab_import_keystore)) },
        text = {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                // Key Type Selector
                ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = !expanded }) {
                    TextField(
                        value = keyTypes[keyStoreType],
                        onValueChange = {},
                        label = { Text(stringResource(R.string.lab_select_type)) },
                        readOnly = true,
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon() },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                    ) {
                        keyTypes.forEachIndexed { index, type ->
                            MenuItem(
                                onClick = {
                                    onTypeChange(index)
                                    expanded = false
                                },
                                text = { Text(type) },
                            )
                        }
                    }
                }

                // Keystore Password
                TextField(
                    value = keyStorePassword,
                    onValueChange = onPasswordChange,
                    label = { Text(stringResource(R.string.lab_keystore_pass)) },
                    visualTransformation = TextFieldDefaults.PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )

                // Keystore File
                TextField(
                    value = if (onFileSelected) stringResource(R.string.lab_file_selected) else "",
                    onValueChange = {},
                    label = { Text(stringResource(R.string.lab_keystore_file)) },
                    readOnly = true,
                    trailingIcon = {
                        TextButton(
                            onClick = onFileClick,
                        ) {
                            Text(stringResource(R.string.lab_select))
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm()
                    onDismiss()
                },
            ) {
                Text(stringResource(R.string.ok))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
            ) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

@Composable
fun KeyStoreAliasDialog(
    onDismiss: () -> Unit,
    aliases: List<String>,
    onConfirm: (String, String) -> Unit,
    stringResource: (Int) -> String,
) {
    var selectedAlias by remember { mutableStateOf(aliases.firstOrNull() ?: "") }
    var keyPassword by remember { mutableStateOf("") }
    var expanded by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.lab_choose_an_alias)) },
        text = {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                // Alias Selector
                ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = !expanded }) {
                    TextField(
                        value = selectedAlias,
                        onValueChange = {},
                        label = { Text(stringResource(R.string.lab_choose_an_alias)) },
                        readOnly = true,
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon() },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = expanded,
                        onDismissRequest = { expanded = false },
                    ) {
                        aliases.forEach { alias ->
                            MenuItem(
                                onClick = {
                                    selectedAlias = alias
                                    expanded = false
                                },
                                text = { Text(alias) },
                            )
                        }
                    }
                }

                // Alias Password
                TextField(
                    value = keyPassword,
                    onValueChange = { keyPassword = it },
                    label = { Text(stringResource(R.string.lab_alias_pass)) },
                    visualTransformation = TextFieldDefaults.PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(selectedAlias, keyPassword)
                    onDismiss()
                },
            ) {
                Text(stringResource(R.string.ok))
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
            ) {
                Text(stringResource(R.string.cancel))
            }
        },
    )
}

fun loadKeyStoreAliases(
    context: Context,
    file: File,
    keyType: Int,
    password: String,
    onResult: (List<String>) -> Unit,
    onError: (String) -> Unit,
) {
    CoroutineScope(Dispatchers.IO).launch {
        try {
            val type = when (keyType) {
                0 -> "JKS"
                1 -> "PKCS12"
                2 -> "BKS"
                else -> "JKS"
            }
            val provider = when (keyType) {
                0 -> null
                1, 2 -> BouncyCastleProvider()
                else -> null
            }
            val keyStore = if (provider != null) {
                KeyStore.getInstance(type, provider)
            } else {
                KeyStore.getInstance(type)
            }
            FileInputStream(file).use { input ->
                keyStore.load(input, password.toCharArray())
            }
            val aliases = keyStore.aliases().asSequence().filter { keyStore.isKeyEntry(it) }.toList()
            kotlinx.coroutines.withContext(Dispatchers.Main) {
                onResult(aliases)
            }
        } catch (e: Exception) {
            kotlinx.coroutines.withContext(Dispatchers.Main) {
                onError(e.message ?: "Failed to read keystore")
            }
        }
    }
}
