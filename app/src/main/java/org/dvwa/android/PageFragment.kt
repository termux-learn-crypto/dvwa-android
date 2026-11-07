package org.dvwa.android

import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import org.dvwa.android.databinding.FragmentPageBinding

/** One DVWA screen (module or info page). Implementations build native views with [Ui]. */
abstract class Page {
    abstract val id: String
    abstract val title: String
    open val vuln: Boolean = true
    open val links: List<String> = emptyList()
    abstract fun build(ui: Ui, f: PageFragment)
    val level: String get() = DvwaApp.I.level
    val app: DvwaApp get() = DvwaApp.I
}

class PageFragment : Fragment() {
    private var _b: FragmentPageBinding? = null
    val b get() = _b!!
    lateinit var page: Page
    private var pickCb: ((Uri?) -> Unit)? = null
    private val picker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri -> pickCb?.invoke(uri); pickCb = null }

    fun pickFile(cb: (Uri?) -> Unit) { pickCb = cb; picker.launch("*/*") }
    fun main(): MainActivity? = activity as? MainActivity

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _b = FragmentPageBinding.inflate(inflater, container, false)
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        page = Pages.byId(arguments?.getString("id") ?: "home")
        b.tvTitle.text = if (page.vuln) "Vulnerability: ${page.title}" else page.title
        b.tvLevel.text = "Security level: ${page.level.replaceFirstChar { it.uppercase() }}"
        b.tvLevel.setBackgroundColor(when (page.level) { "low" -> 0xFFC62828.toInt(); "medium" -> 0xFFEF6C00.toInt(); "high" -> 0xFF1565C0.toInt(); else -> 0xFF2E7D32.toInt() })
        b.tvLevel.visibility = if (page.vuln) View.VISIBLE else View.GONE
        b.buttonBar.visibility = if (page.vuln) View.VISIBLE else View.GONE
        b.btnSource.setOnClickListener { startActivity(TextActivity.source(requireContext(), page.id, page.title, page.level)) }
        b.btnCompare.setOnClickListener { startActivity(TextActivity.source(requireContext(), page.id, page.title, "all")) }
        b.btnHelp.setOnClickListener { startActivity(TextActivity.help(requireContext(), page.id, page.title)) }
        b.tvMoreInfoHeader.visibility = if (page.links.isEmpty()) View.GONE else View.VISIBLE
        for (l in page.links) {
            b.moreInfo.addView(TextView(requireContext()).apply {
                text = "• $l"; textSize = 13f; setTextColor(0xFF1565C0.toInt()); setPadding(0, 6, 0, 6)
                setTextIsSelectable(true)
            })
        }
        try {
            page.build(Ui(requireContext(), b.content), this)
        } catch (e: Exception) {
            b.content.addView(TextView(requireContext()).apply { text = "Error building page: $e" })
        }
    }

    override fun onDestroyView() { super.onDestroyView(); _b = null }

    companion object {
        fun of(id: String) = PageFragment().apply { arguments = Bundle().apply { putString("id", id) } }
    }
}

/** Shows an external URL the app refuses to open (offline sandbox). */
fun externalNotice(f: PageFragment, url: String) {
    OutBox.alert(f.requireContext(), "External navigation blocked",
        "The app would now send the victim to:\n\n$url\n\nDVWA Offline never contacts external hosts (no INTERNET permission). If this was an Open Redirect or an exfiltration, the attack worked.")
}

