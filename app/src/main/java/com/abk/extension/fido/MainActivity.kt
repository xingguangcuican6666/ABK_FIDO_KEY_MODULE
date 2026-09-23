package com.abk.extension.fido

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.format.DateUtils
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import com.google.android.material.color.DynamicColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * The whole app in one screen: the master switch, the wireless relay, and the
 * keys the driver is holding.
 *
 * Every fact on this screen comes from root — the persisted store blob and the
 * driver's sysfs nodes — so all of it is read on [io] and only the rendering
 * happens on the main thread. The background service stays the owner of policy:
 * this activity writes [FidoSettings] and then asks the service to apply it.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var settings: FidoSettings
    private lateinit var clients: LanClientRegistry
    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private lateinit var masterSwitch: MaterialSwitch
    private lateinit var wirelessSwitch: MaterialSwitch
    private lateinit var wirelessRow: View
    private lateinit var providerSection: View
    private lateinit var providerRow: View
    private lateinit var providerSummary: TextView
    private lateinit var statusSummary: TextView
    private lateinit var pairingSummary: TextView
    private lateinit var lanSummary: TextView
    private lateinit var keysContainer: LinearLayout
    private lateinit var keysEmpty: TextView

    private var credentials: List<FidoCredentialRecord> = emptyList()
    private var pairingCode: String = ""
    private var providerStatus: CredentialProviderControl.Status? = null
    private var providerRootAvailable = false
    private var busy = false

    /** An archive the user has authorized, waiting for a destination document. */
    private var exportPending: ExportRequest? = null

    private class ExportRequest(val records: List<FidoCredentialRecord>, val passphrase: CharArray)

    private val createDocument =
        registerForActivityResult(ActivityResultContracts.CreateDocument(KeyArchive.MIME_TYPE)) { uri ->
            val request = exportPending
            exportPending = null
            if (uri != null && request != null) writeArchive(uri, request)
        }

    private val openDocument =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) readArchive(uri)
        }

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DynamicColors.applyToActivityIfAvailable(this)
        setContentView(R.layout.activity_main)
        settings = FidoSettings.of(this)
        clients = LanClientRegistry.of(this)
        bindViews()
        // Opening the app is also the moment to make sure the service that owns
        // root, policy and the auth prompt is actually running.
        FidoSyncService.requestSync(this, "app_open")
        askForNotificationsIfNeeded()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }

    private fun bindViews() {
        masterSwitch = findViewById(R.id.masterSwitch)
        wirelessSwitch = findViewById(R.id.wirelessSwitch)
        wirelessRow = findViewById(R.id.wirelessRow)
        providerSection = findViewById(R.id.providerSection)
        providerRow = findViewById(R.id.providerRow)
        providerSummary = findViewById(R.id.providerSummary)
        statusSummary = findViewById(R.id.statusSummary)
        pairingSummary = findViewById(R.id.pairingSummary)
        lanSummary = findViewById(R.id.lanClientsSummary)
        keysContainer = findViewById(R.id.keysContainer)
        keysEmpty = findViewById(R.id.keysEmpty)

        // The switches are set from settings on every refresh, so react to the
        // click rather than to the checked state: a listener on the state would
        // fire for our own writes too.
        masterSwitch.setOnClickListener {
            settings.fidoEnabled = masterSwitch.isChecked
            FidoSyncService.applyPolicy(this)
            refresh()
        }
        wirelessRow.setOnClickListener {
            if (!settings.fidoEnabled) return@setOnClickListener
            settings.wirelessEnabled = !settings.wirelessEnabled
            FidoSyncService.applyPolicy(this)
            refresh()
        }
        // The system only routes passkey requests to a provider on Android 14+,
        // so the whole row is meaningless before that.
        val providerSupported = CredentialProviderControl.supported
        providerSection.isVisible = providerSupported
        providerRow.isVisible = providerSupported
        providerRow.setOnClickListener { showProviderOptions() }
        findViewById<View>(R.id.pairingRow).setOnClickListener { showPairingCode() }
        findViewById<View>(R.id.lanClientsRow).setOnClickListener {
            startActivity(Intent(this, LanClientsActivity::class.java))
        }
        findViewById<View>(R.id.addKeyRow).setOnClickListener { showAddKeyHelp() }
        findViewById<View>(R.id.importRow).setOnClickListener {
            openDocument.launch(arrayOf("*/*"))
        }
        findViewById<View>(R.id.exportAllRow).setOnClickListener {
            askExportPassphrase(credentials)
        }
    }

    private class Snapshot(
        val driverPresent: Boolean,
        val bound: Boolean?,
        val kernelCount: Int?,
        val store: FidoStoreBlob?,
        val pairingCode: String,
        val authorized: Int,
        val pending: Int,
        val total: Int,
        val providerStatus: CredentialProviderControl.Status?,
        val rootAvailable: Boolean,
    )

    private fun refresh() {
        val fidoEnabled = settings.fidoEnabled
        masterSwitch.isChecked = fidoEnabled
        wirelessSwitch.isChecked = settings.wirelessEnabled
        wirelessRow.isEnabled = fidoEnabled
        wirelessRow.alpha = if (fidoEnabled) 1f else 0.4f
        io.execute {
            val providerSupported = CredentialProviderControl.supported
            val snapshot = Snapshot(
                driverPresent = FidoKernelBridge.isPresent(),
                bound = FidoKernelBridge.readBound(),
                kernelCount = FidoKernelBridge.readCredentialCount(),
                store = FidoStoreManager.read(),
                pairingCode = RootShell.readTextFile(PAIRING_CODE_PATH).stdout.trim(),
                authorized = clients.authorizedCount(),
                pending = clients.pendingCount(),
                total = clients.list().size,
                providerStatus = if (providerSupported) CredentialProviderControl.read(this) else null,
                rootAvailable = providerSupported && RootShell.isRootAvailable(),
            )
            main.post { if (!isFinishing && !isDestroyed) render(snapshot) }
        }
    }

    private fun render(snapshot: Snapshot) {
        credentials = snapshot.store?.credentials() ?: emptyList()
        pairingCode = snapshot.pairingCode

        val lines = ArrayList<String>(3)
        if (!snapshot.driverPresent) {
            lines += getString(R.string.status_driver_missing)
        } else {
            val count = snapshot.kernelCount ?: credentials.size
            lines += getString(R.string.status_keys, count, FidoStoreBlob.MAX_CREDS)
            lines += getString(
                if (snapshot.bound == true) R.string.status_host_connected else R.string.status_host_waiting
            )
        }
        if (snapshot.store == null) lines += getString(R.string.status_root_unavailable)
        if (!settings.fidoEnabled) lines += getString(R.string.status_disabled)
        statusSummary.text = lines.joinToString("\n")

        providerStatus = snapshot.providerStatus
        providerRootAvailable = snapshot.rootAvailable
        snapshot.providerStatus?.let { status ->
            providerSummary.text = when {
                status.preferred -> getString(R.string.provider_status_preferred)
                status.enabled -> getString(R.string.provider_status_enabled)
                status.otherPreferredLabel != null ->
                    getString(R.string.provider_status_disabled_with_current, status.otherPreferredLabel)
                else -> getString(R.string.provider_status_disabled)
            }
        }

        pairingSummary.text = if (snapshot.pairingCode.isBlank()) {
            getString(R.string.pairing_code_unavailable)
        } else {
            getString(R.string.pairing_code_hidden)
        }
        lanSummary.text = if (snapshot.total == 0) {
            getString(R.string.lan_clients_summary_none)
        } else {
            getString(R.string.lan_clients_summary, snapshot.authorized, snapshot.pending)
        }

        keysContainer.removeAllViews()
        keysEmpty.isVisible = credentials.isEmpty()
        keysEmpty.setText(if (snapshot.store == null) R.string.keys_unreadable else R.string.keys_empty)
        credentials.forEach(::addKeyRow)
    }

    private fun addKeyRow(record: FidoCredentialRecord) {
        val row = layoutInflater.inflate(R.layout.item_fido_key, keysContainer, false)
        row.findViewById<TextView>(R.id.keyTitle).text = record.siteLabel(this)
        row.findViewById<TextView>(R.id.keyAccount).text = record.accountLabel(this)
        val lastUsed = settings.lastUsed(record.rpId)
        row.findViewById<TextView>(R.id.keyLastUsed).text = if (lastUsed <= 0L) {
            getString(R.string.key_never_used)
        } else {
            getString(R.string.key_last_used, DateUtils.getRelativeTimeSpanString(this, lastUsed))
        }
        val overflow = row.findViewById<ImageButton>(R.id.keyOverflow)
        overflow.contentDescription = getString(R.string.key_menu_title, record.siteLabel(this))
        overflow.setOnClickListener { showKeyMenu(overflow, record) }
        row.setOnClickListener { showKeyMenu(overflow, record) }
        keysContainer.addView(row)
    }

    private fun showKeyMenu(anchor: View, record: FidoCredentialRecord) {
        val menu = PopupMenu(this, anchor)
        menu.inflate(R.menu.key_row)
        menu.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.menu_key_rename -> showRenameDialog(record)
                R.id.menu_key_export -> askExportPassphrase(listOf(record))
                R.id.menu_key_delete -> confirmDelete(record)
                else -> return@setOnMenuItemClickListener false
            }
            true
        }
        menu.show()
    }

    private fun showRenameDialog(record: FidoCredentialRecord) {
        val view = layoutInflater.inflate(R.layout.dialog_rename_key, null)
        val nameField = view.findViewById<TextInputEditText>(R.id.userName)
        val displayField = view.findViewById<TextInputEditText>(R.id.userDisplay)
        nameField.setText(record.userName)
        displayField.setText(record.userDisplay)
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.rename_dialog_title)
            .setView(view)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_save) { _, _ ->
                val name = nameField.text?.toString().orEmpty().trim()
                val display = displayField.text?.toString().orEmpty().trim()
                runStoreEdit(getString(R.string.rename_done)) {
                    FidoStoreManager.rename(record.slot, name, display)
                }
            }
            .show()
    }

    private fun confirmDelete(record: FidoCredentialRecord) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.delete_dialog_title, record.siteLabel(this)))
            .setMessage(R.string.delete_dialog_message)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                runStoreEdit(getString(R.string.delete_done)) {
                    val result = FidoStoreManager.delete(record.slot)
                    // The "last used" note is ours, not the driver's, so drop it
                    // once no key of that site is left.
                    if (result is StoreEditResult.Success &&
                        FidoStoreManager.read()?.credentials()?.none { it.rpId == record.rpId } != false
                    ) {
                        settings.forgetUsage(record.rpId)
                    }
                    result
                }
            }
            .show()
    }

    /**
     * Run one store edit off the main thread. A store edit ends in the driver
     * adopting the blob, which takes a few hundred milliseconds, so the screen
     * refuses to start a second one while the first is in flight.
     */
    private fun runStoreEdit(success: String, work: () -> StoreEditResult) {
        if (busy) {
            toast(getString(R.string.working))
            return
        }
        busy = true
        toast(getString(R.string.working))
        io.execute {
            val result = runCatching(work).getOrElse { StoreEditResult.Failure(it.messageOrType()) }
            main.post {
                busy = false
                if (isFinishing || isDestroyed) return@post
                when (result) {
                    is StoreEditResult.Success -> toast(success)
                    is StoreEditResult.Failure -> alert(getString(R.string.edit_failed, result.message))
                }
                refresh()
            }
        }
    }

    private fun askExportPassphrase(records: List<FidoCredentialRecord>) {
        if (records.isEmpty()) {
            toast(getString(R.string.no_keys_to_export))
            return
        }
        val view = layoutInflater.inflate(R.layout.dialog_passphrase, null)
        val field = view.findViewById<TextInputEditText>(R.id.passphrase)
        val confirmField = view.findViewById<TextInputEditText>(R.id.passphraseConfirm)
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.passphrase_export_title)
            .setMessage(R.string.passphrase_export_message)
            .setView(view)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_export, null)
            .create()
        // The positive button is wired after the dialog exists so a rejected
        // passphrase leaves the typed text in place instead of closing.
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val passphrase = field.text?.toString().orEmpty()
                val confirmation = confirmField.text?.toString().orEmpty()
                when {
                    passphrase.length < MIN_PASSPHRASE -> toast(getString(R.string.passphrase_too_short))
                    passphrase != confirmation -> toast(getString(R.string.passphrase_mismatch))
                    else -> {
                        dialog.dismiss()
                        exportPending = ExportRequest(records, passphrase.toCharArray())
                        createDocument.launch(suggestedFileName(records))
                    }
                }
            }
        }
        dialog.show()
    }

    private fun suggestedFileName(records: List<FidoCredentialRecord>): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())
        val label = if (records.size == 1) {
            // The file name stays ASCII, so it comes from the raw rpId rather
            // than the label the list shows.
            records[0].rpId.lowercase(Locale.US).replace(Regex("[^a-z0-9.-]"), "-").take(32)
                .ifBlank { "key" }
        } else {
            "all"
        }
        return "abk-fido-$label-$stamp.${KeyArchive.FILE_EXTENSION}"
    }

    private fun writeArchive(uri: Uri, request: ExportRequest) {
        io.execute {
            val outcome = runCatching {
                val bytes = KeyArchive.export(request.records, request.passphrase)
                contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                    ?: throw IllegalStateException("could not open the chosen file")
            }
            request.passphrase.fill(' ')
            main.post {
                if (isFinishing || isDestroyed) return@post
                outcome.fold(
                    onSuccess = { toast(getString(R.string.export_done, request.records.size)) },
                    onFailure = { alert(getString(R.string.export_failed, it.messageOrType())) },
                )
            }
        }
    }

    private fun readArchive(uri: Uri) {
        io.execute {
            val bytes = runCatching {
                contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw IllegalStateException("could not open the chosen file")
            }
            main.post {
                if (isFinishing || isDestroyed) return@post
                bytes.fold(
                    onSuccess = { askImportPassphrase(it) },
                    onFailure = { alert(getString(R.string.import_failed, it.messageOrType())) },
                )
            }
        }
    }

    private fun askImportPassphrase(bytes: ByteArray) {
        val view = layoutInflater.inflate(R.layout.dialog_passphrase, null)
        view.findViewById<View>(R.id.confirmContainer).isVisible = false
        val field = view.findViewById<TextInputEditText>(R.id.passphrase)
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.passphrase_import_title)
            .setMessage(R.string.passphrase_import_message)
            .setView(view)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_import) { _, _ ->
                val passphrase = field.text?.toString().orEmpty().toCharArray()
                importArchive(bytes, passphrase)
            }
            .show()
    }

    private fun importArchive(bytes: ByteArray, passphrase: CharArray) {
        if (busy) {
            toast(getString(R.string.working))
            return
        }
        busy = true
        toast(getString(R.string.working))
        io.execute {
            val outcome = runCatching { KeyArchive.import(bytes, passphrase) }
                .mapCatching { FidoStoreManager.import(it) }
            passphrase.fill(' ')
            main.post {
                busy = false
                if (isFinishing || isDestroyed) return@post
                outcome.fold(
                    onSuccess = { report ->
                        val result = report.result
                        when {
                            result is StoreEditResult.Failure ->
                                alert(getString(R.string.import_failed, result.message))
                            report.imported == 0 -> toast(getString(R.string.import_nothing_new))
                            else -> toast(getString(R.string.import_done, report.imported, report.skipped))
                        }
                    },
                    onFailure = { alert(getString(R.string.import_failed, it.messageOrType())) },
                )
                refresh()
            }
        }
    }

    private fun showPairingCode() {
        if (pairingCode.isBlank()) {
            alert(getString(R.string.pairing_code_unavailable))
            return
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.pairing_code_title)
            .setMessage(pairingCode)
            .setNegativeButton(R.string.action_close, null)
            .setPositiveButton(R.string.action_copy) { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText(getString(R.string.pairing_code_title), pairingCode))
                toast(getString(R.string.pairing_code_copied))
            }
            .show()
    }

    /**
     * There is no way for the app to mint a credential on its own: a key is
     * created by the site asking for one. Say so, and offer the one thing that
     * does add a key from here.
     */
    private fun showAddKeyHelp() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.add_key_title)
            .setMessage(R.string.add_key_message)
            .setNegativeButton(R.string.action_close, null)
            .setPositiveButton(R.string.action_import) { _, _ -> openDocument.launch(arrayOf("*/*")) }
            .show()
    }

    /**
     * The system provider row. It always offers the safe path — the system
     * settings screen where the user picks providers by hand — and, when root
     * is available, a one-tap switch that makes this app the preferred provider
     * (or hands the slot back). The switch changes which app answers passkey
     * requests, so it stays behind this explicit choice.
     */
    private fun showProviderOptions() {
        val status = providerStatus
        val message = when {
            status == null -> getString(R.string.provider_status_disabled)
            status.preferred -> getString(R.string.provider_status_preferred)
            status.enabled -> getString(R.string.provider_status_enabled)
            status.otherPreferredLabel != null ->
                getString(R.string.provider_status_disabled_with_current, status.otherPreferredLabel)
            else -> getString(R.string.provider_status_disabled)
        }
        val builder = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.provider_row_title)
            .setMessage(message)
            .setNeutralButton(R.string.provider_action_open_settings) { _, _ -> openCredentialSettings() }
            .setNegativeButton(R.string.action_close, null)
        if (providerRootAvailable && status != null) {
            if (status.preferred) {
                builder.setPositiveButton(R.string.provider_action_restore) { _, _ -> changeProvider(enable = false) }
            } else {
                builder.setPositiveButton(R.string.provider_action_set_preferred) { _, _ -> changeProvider(enable = true) }
            }
        }
        builder.show()
    }

    private fun openCredentialSettings() {
        // ACTION_CREDENTIAL_PROVIDER wants a package: data URI to focus on us;
        // fall back to the bare action, then to the top-level settings, so the
        // user always lands somewhere they can change the provider.
        val targets = listOf(
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER).setData(Uri.parse("package:$packageName")),
            Intent(Settings.ACTION_CREDENTIAL_PROVIDER),
            Intent(Settings.ACTION_SETTINGS),
        )
        for (intent in targets) {
            if (runCatching { startActivity(intent) }.isSuccess) return
        }
        toast(getString(R.string.provider_settings_unavailable))
    }

    private fun changeProvider(enable: Boolean) {
        toast(getString(R.string.working))
        io.execute {
            val ok = runCatching {
                if (enable) CredentialProviderControl.enableAsPreferred(this) else CredentialProviderControl.restore(this)
            }.getOrDefault(false)
            main.post {
                if (isFinishing || isDestroyed) return@post
                if (ok) {
                    toast(getString(if (enable) R.string.provider_enable_done else R.string.provider_restore_done))
                } else {
                    alert(getString(R.string.provider_change_failed))
                }
                refresh()
            }
        }
    }

    private fun askForNotificationsIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        // Without it the "a computer wants to use the key" alert is silent.
        if (!granted) requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun alert(message: String) {
        MaterialAlertDialogBuilder(this)
            .setMessage(message)
            .setPositiveButton(R.string.action_close, null)
            .show()
    }

    private companion object {
        const val PAIRING_CODE_PATH = "/metadata/abk_fido_pairing_code"
        const val MIN_PASSPHRASE = 8
    }
}

/** A message worth showing when an exception carries none. */
internal fun Throwable.messageOrType(): String =
    message?.takeIf { it.isNotBlank() } ?: this::class.java.simpleName
