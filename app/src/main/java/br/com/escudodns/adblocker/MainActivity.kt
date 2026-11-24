package br.com.escudodns.adblocker

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    private var isVpnActive = false
    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        requestVpnPermissionAndStart()
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startAdBlockService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        toggleButton = findViewById(R.id.toggleButton)

        val rulesSummary = findViewById<TextView>(R.id.rulesCountText)
        rulesSummary.text =
            "Regras ativas: ${BlocklistCatalog.blockedDomains.size} bloqueios · ${BlocklistCatalog.allowedDomains.size} exceções"

        toggleButton.setOnClickListener {
            if (isVpnActive) {
                stopAdBlockService()
            } else {
                ensurePermissionsAndStart()
            }
        }
    }

    private fun ensurePermissionsAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        requestVpnPermissionAndStart()
    }

    private fun requestVpnPermissionAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startAdBlockService()
        }
    }

    private fun startAdBlockService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
        isVpnActive = true
        statusText.text = "Proteção ativa (DNS local filtrando anúncios)"
        toggleButton.text = "Desativar Proteção"
    }

    private fun stopAdBlockService() {
        val intent = Intent(this, AdBlockVpnService::class.java).apply {
            action = AdBlockVpnService.ACTION_STOP
        }
        startService(intent)
        isVpnActive = false
        statusText.text = "Proteção pausada"
        toggleButton.text = "Ativar Bloqueio de Anúncios"
    }
}
