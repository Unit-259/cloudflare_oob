# Cloudflare OOB Injector Extension (Jython-compatible)
# 
# This extension adds:
#   - GUI tab with text field for Cloudflare Worker URL
#   - Checkbox to enable/disable injection
#   - Custom headers injection

from burp import IBurpExtender, IHttpListener, ITab
from java.util import UUID
from java.io import PrintWriter
from java.net import URLEncoder, URL
from javax.swing import (
    JPanel, JScrollPane, JTable, BorderFactory, JLabel, 
    JTextField, Box, JCheckBox, BoxLayout, JButton, 
    Timer
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
from java.lang import Runnable
import threading
import json

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)

        callbacks.setExtensionName("Cloudflare OOB Injector")
        callbacks.registerHttpListener(self)

        # Default values
        self.worker_base = "https://your-worker.workers.dev/oob"
        self.inject_enabled = False
        self.custom_headers = []
        self.payloads = []

        # ================================
        # Build the main panel
        # ================================
        self.panel = JPanel(BorderLayout())
        self.panel.setBorder(BorderFactory.createTitledBorder("Injected OOB Payloads"))

        # Table to show OOB injections
        self.columns = ["ID", "Payload", "Target URL"]
        self.model = DefaultTableModel(self.columns, 0)
        self.table = JTable(self.model)
        self.scroll = JScrollPane(self.table)

        # ----------------------------------------------------------------------
        # Worker URL row
        # ----------------------------------------------------------------------
        self.worker_panel = Box.createHorizontalBox()
        self.worker_panel.add(JLabel("Cloudflare Worker URL: "))
        self.worker_input = JTextField(self.worker_base, 40)
        self.worker_input.actionPerformed = self.updateWorkerURL
        self.worker_panel.add(self.worker_input)

        # ----------------------------------------------------------------------
        # Control buttons (Enable/Disable, Clear output)
        # ----------------------------------------------------------------------
        self.ctrl_panel = Box.createHorizontalBox()
        self.enable_btn = JButton("Enable Injection", actionPerformed=self.toggleInjection)
        self.clear_btn = JButton("Clear Output", actionPerformed=self.clearOutput)
        self.ctrl_panel.add(self.enable_btn)
        self.ctrl_panel.add(self.clear_btn)

        # ----------------------------------------------------------------------
        # Checkboxes for injection
        # ----------------------------------------------------------------------
        self.checkbox_panel = Box.createHorizontalBox()
        self.ua_check = JCheckBox("User-Agent", True)
        self.ref_check = JCheckBox("Referer", False)
        self.cookie_check = JCheckBox("Cookie", False)
        self.host_check = JCheckBox("Host", False)
        self.checkbox_panel.add(self.ua_check)
        self.checkbox_panel.add(self.ref_check)
        self.checkbox_panel.add(self.cookie_check)
        self.checkbox_panel.add(self.host_check)

        # ----------------------------------------------------------------------
        # Custom header panel
        # ----------------------------------------------------------------------
        self.custom_input = JTextField("X-My-Custom-Header", 20)
        self.add_custom_btn = JButton("Add Custom Header", actionPerformed=self.addCustomHeader)
        self.custom_input_panel = Box.createHorizontalBox()
        self.custom_input_panel.add(self.custom_input)
        self.custom_input_panel.add(self.add_custom_btn)

        self.custom_list_panel = JPanel()
        self.custom_list_panel.setLayout(BoxLayout(self.custom_list_panel, BoxLayout.Y_AXIS))

        self.custom_panel = Box.createVerticalBox()
        self.custom_panel.add(self.custom_input_panel)
        self.custom_panel.add(self.custom_list_panel)

        # ----------------------------------------------------------------------
        # Assemble top area
        # ----------------------------------------------------------------------
        top_wrapper = JPanel()
        top_wrapper.setLayout(BoxLayout(top_wrapper, BoxLayout.Y_AXIS))
        top_wrapper.add(self.worker_panel)
        top_wrapper.add(self.ctrl_panel)
        top_wrapper.add(self.checkbox_panel)
        top_wrapper.add(self.custom_panel)

        self.panel.add(top_wrapper, BorderLayout.NORTH)
        self.panel.add(self.scroll, BorderLayout.CENTER)

        # Add this panel as a Burp tab
        callbacks.addSuiteTab(self)

        self.stdout.println("[OOB] Extension loaded. Injection disabled by default.")

    # ================================
    # ITab methods
    # ================================
    def getTabCaption(self):
        return "OOB Tracker"

    def getUiComponent(self):
        return self.panel

    # ================================
    # Event handlers / helper methods
    # ================================
    def updateWorkerURL(self, event):
        new_url = self.worker_input.getText().strip()
        if new_url:
            self.worker_base = new_url
            self.stdout.println("[OOB] Updated worker URL to: %s" % self.worker_base)

    def toggleInjection(self, event):
        self.inject_enabled = not self.inject_enabled
        status = "enabled" if self.inject_enabled else "disabled"
        self.enable_btn.setText("Disable Injection" if self.inject_enabled else "Enable Injection")
        self.stdout.println("[OOB] Injection {}".format(status))

    def clearOutput(self, event):
        self.model.setRowCount(0)
        self.payloads = []
        self.stdout.println("[OOB] Cleared injection output table.")

    def addCustomHeader(self, event):
        key = self.custom_input.getText().strip()
        if key:
            self.custom_headers.append(key)
            self.stdout.println("[+] Added custom header: {}".format(key))
            self.custom_input.setText("")
            btn = JButton("Remove {}".format(key), actionPerformed=lambda e, k=key: self.removeCustomHeader(k))
            self.custom_list_panel.add(btn)
            self.panel.revalidate()

    def removeCustomHeader(self, key):
        self.custom_headers = [h for h in self.custom_headers if h != key]
        self.custom_list_panel.removeAll()
        for k in self.custom_headers:
            btn = JButton("Remove {}".format(k), actionPerformed=lambda e, k=k: self.removeCustomHeader(k))
            self.custom_list_panel.add(btn)
        self.panel.revalidate()
        self.panel.repaint()
        self.stdout.println("[-] Removed custom header: {}".format(key))

    def generate_oob_payload(self):
        unique_id = UUID.randomUUID().toString().replace("-", "")[:8]
        return "{}?id={}".format(self.worker_base, unique_id), unique_id

    # ================================
    # IHttpListener method
    # ================================
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Called by Burp for every request/response. We'll:
          1) Check if injection is enabled
          2) Mutate headers/body with OOB payload
        """
        if not messageIsRequest or not self.inject_enabled:
            return

        analyzedRequest = self._helpers.analyzeRequest(messageInfo)
        url = analyzedRequest.getUrl().toString().lower()

        # Get the request bytes and parse headers
        request = messageInfo.getRequest()
        headers = analyzedRequest.getHeaders()
        body = request[analyzedRequest.getBodyOffset():].tostring()

        # Build OOB payload
        oob_url, oob_id = self.generate_oob_payload()

        # Update headers based on checkboxes
        new_headers = []
        for header in headers:
            lower = header.lower()
            if lower.startswith("user-agent:") and self.ua_check.isSelected():
                new_headers.append("User-Agent: {}".format(oob_url))
            elif lower.startswith("referer:") and self.ref_check.isSelected():
                new_headers.append("Referer: {}".format(oob_url))
            elif lower.startswith("cookie:") and self.cookie_check.isSelected():
                new_headers.append("Cookie: oob={}".format(oob_url))
            elif lower.startswith("host:") and self.host_check.isSelected():
                new_headers.append("Host: {}".format(oob_url))
            else:
                new_headers.append(header)

        # Add a custom "X-Inject-OOB" header
        new_headers.append("X-Inject-OOB: {}".format(oob_url))
        for key in self.custom_headers:
            new_headers.append("{}: {}".format(key, oob_url))

        if body:
            body += "&debug_oob={}".format(URLEncoder.encode(oob_url, "UTF-8"))

        new_request = self._helpers.buildHttpMessage(new_headers, body)
        messageInfo.setRequest(new_request)

        self.payloads.append([oob_id, oob_url, url])
        self.model.addRow([oob_id, oob_url, url])
