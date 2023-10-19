package com.android.mdl.appreader.settings

import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.platform.ComposeView
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.navigation.fragment.findNavController
import com.android.mdl.appreader.VerifierApp
import com.android.mdl.appreader.theme.ReaderAppTheme

class CaCertificatesFragment : Fragment() {

    private val viewModel: CaCertificatesViewModel by activityViewModels {
        CaCertificatesViewModel.factory(requireContext())
    }

    private val browseCertificateLauncher =
        registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
            uris.forEach { uri -> importCertificate(uri) }
        }


    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return ComposeView(requireContext()).apply {
            setContent {
                val state = viewModel.screenState.collectAsState().value
                viewModel.loadCertificates()
                ReaderAppTheme {
                    CaCertificatesScreen(
                        screenState = state,
                        onSelectCertificate = {
                            viewModel.setCurrentCertificateItem(it)
                            openDetails()
                        },
                        onImportCertificate = {
                            fileDialog()
                            viewModel.loadCertificates()
                        }
                    )
                }
            }
        }
    }

    private fun openDetails() {
        val destination = CaCertificatesFragmentDirections.toCaCertificateDetails()
        findNavController().navigate(destination)
    }

    private fun fileDialog() {
        browseCertificateLauncher.launch(arrayOf("*/*")) // TODO: maybe more specific...
    }

    private fun importCertificate(uri: Uri) {
        try {
            val inputStream = this.requireContext().contentResolver.openInputStream(uri)
            if (inputStream != null) {
                VerifierApp.caCertificateStoreInstance.save(inputStream.readBytes())
                // force the trust manager to reload the certificates and vicals
                VerifierApp.trustManagerInstance.reset()
            }
        } catch (e: Throwable) {
            // TODO: how to show errors?
        }
    }
}