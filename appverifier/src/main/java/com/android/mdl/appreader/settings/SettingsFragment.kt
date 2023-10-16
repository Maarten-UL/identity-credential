package com.android.mdl.appreader.settings

import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.preference.PreferenceManager
import com.android.mdl.appreader.issuerauth.CaCertificateStore
import com.android.mdl.appreader.issuerauth.TrustManagerImplementation
import com.android.mdl.appreader.theme.ReaderAppTheme

class SettingsFragment : Fragment() {

    private val userPreferences by lazy {
        val sharedPreferences = PreferenceManager.getDefaultSharedPreferences(requireContext())
        UserPreferences(sharedPreferences)
    }
    private val viewModel: SettingsViewModel by viewModels {
        SettingsViewModel.factory(userPreferences)
    }

    private val browseCertificateLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) {
        uri ->
        if (uri != null) {
            importCertificate(uri)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return ComposeView(requireContext()).apply {
            setContent {
                val state = viewModel.screenState.collectAsState().value
                viewModel.loadSettings()
                ReaderAppTheme {
                    SettingsScreen(
                        modifier = Modifier.fillMaxSize(),
                        screenState = state,
                        onAutoCloseConnectionChanged = viewModel::onAutoCloseConnectionUpdated,
                        onUseL2CAPChanged = viewModel::onBleL2capUpdated,
                        onBLEServiceCacheChanged = viewModel::onBleClearCacheUpdated,
                        onHttpTransferChanged = viewModel::onHttpTransferUpdated,
                        onBLECentralClientModeChanged = viewModel::onBleCentralClientModeUpdated,
                        onBLEPeripheralServerModeChanged = viewModel::onBlePeripheralClientModeUpdated,
                        onWifiAwareTransferChanged = viewModel::onWifiAwareUpdated,
                        onNfcTransferChanged = viewModel::onNfcTransferUpdated,
                        onDebugLoggingChanged = viewModel::onDebugLoggingUpdated,
                        onChangeReaderAuthentication = viewModel::onReaderAuthenticationUpdated,
                        onAddCertificate = { fileDialog() }
                    )
                }
            }
        }
    }

    private fun fileDialog(){
        browseCertificateLauncher.launch(arrayOf("*/*")) // TODO: maybe more specific...
    }

    private fun importCertificate(uri: Uri){
        try {
        val inputStream = this.requireContext().contentResolver.openInputStream(uri)
        if (inputStream != null) {
            CaCertificateStore.save(requireContext(), inputStream.readBytes() )
            // force the trust manager to reload the certificates
            TrustManagerImplementation.getInstance(requireContext()).reset()
            Toast.makeText(requireContext(), "CA Certificate Loaded", Toast.LENGTH_SHORT)
        }} catch (e:Throwable){
            // TODO: how to show errors?
        }
    }
}