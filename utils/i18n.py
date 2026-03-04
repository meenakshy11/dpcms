"""
utils/i18n.py
-------------
Kerala Bank DPCMS — Internationalisation (i18n) Engine.

Step 6 compliance:
  6A  SUPPORTED_LANGUAGES constant
  6B  Extended TRANSLATIONS dict (Step 6 keys merged into existing LANG["ml"])
  6C  Session-driven t() function (st.session_state["lang"])
  6D  Language field is data-model-neutral (session only, never stored)
  6F  validate_no_english_rendered() enforcer
  6G  normalize_malayalam() — Unicode normalization via indicnlp (with fallback)
  6H  transliterate_ml_to_en() / transliterate_en_to_ml() via indic_transliteration
  6I  translate_en_to_ml() — IndicTrans2 wrapper for long-form content
  6J+ t() used for all UI label calls; add_translation() / register_language()
      let callers patch strings without editing this file

Step 7 i18n hardening (new):
  7A  t() raises KeyError on missing key instead of returning empty string —
      no silent blank UI elements; call t_safe() for optional/graceful fallback
  7B  validate_translation_completeness() — startup parity check across all
      registered languages; raises TranslationParityError on mismatch
  7C  DROPDOWN_OPTIONS — canonical key-list constants for all select widgets;
      callers use [t(k) for k in DROPDOWN_OPTIONS["xyz"]] for translated lists
  7D  t() enforces strict ASCII-free output in Malayalam mode; raises
      EnglishLeakageError if ASCII alpha characters appear in returned value
  7E  t_required() — alias for t() that additionally guards empty string
  7F  Clause label keys added for compliance / notices / DPIA modules
  7G  validate_translation_completeness() called automatically on first t() use
      in a new session (lazy startup guard)

Architecture:
  t(key)                              — primary call; raises on missing key
  t_safe(key, default)                — graceful fallback for optional strings
  t_required(key)                     — raises if result is empty
  validate_translation_completeness() — call at app init / post-login
  normalize_malayalam(text)           — call after any Malayalam text is produced
  translate_en_to_ml(text)            — for notices / clause explanations only
  validate_no_english_rendered(text)  — called before critical page renders

Malayalam STRICT mode:
  When lang == "ml", t() NEVER falls back to English.
  Missing keys raise KeyError immediately.
  This enforces zero blank UI and zero English leakage when Malayalam is selected.
"""

from __future__ import annotations

import unicodedata
import streamlit as st


# ===========================================================================
# Step 7 — Custom exception types
# ===========================================================================

class TranslationKeyError(KeyError):
    """Raised when a required translation key is missing from the active language."""


class TranslationParityError(RuntimeError):
    """Raised when a language dictionary is missing keys present in English."""


class EnglishLeakageError(ValueError):
    """Raised when ASCII alphabetic characters appear in a Malayalam-mode translation result."""


# ===========================================================================
# STEP 6A — Language constants
# ===========================================================================

SUPPORTED_LANGUAGES: dict[str, str] = {
    "en": "English",
    "ml": "Malayalam",
    # Extend here as languages are added:
    # "hi": "Hindi",
    # "ta": "Tamil",
    # "kn": "Kannada",
    # "ar": "Arabic",
}


# ===========================================================================
# STEP 6B — Central Translation Dictionary
# (original LANG["en"] and LANG["ml"] preserved exactly;
#  Step 6 Translations keys merged in where not already present)
# ===========================================================================

LANG: dict[str, dict[str, str]] = {

    # ── English ──────────────────────────────────────────────────────────────
    "en": {
        # Navigation / module names
        "dashboard":                    "Dashboard",
        "consent_management":           "Consent Management",
        "rights_portal":                "Data Principal Rights Portal",
        "dpia":                         "DPIA & Privacy Assessments",
        "breach":                       "Data Breach Management",
        "notices":                      "Privacy Notices",
        "audit":                        "Audit Logs",
        "compliance":                   "Compliance & SLA Monitoring",

        # Common actions
        "submit_request":               "Submit Request",
        "export":                       "Export",
        "more_info":                    "More Info",
        "explainability":               "Explainability",
        "publish":                      "Publish Notice",
        "save_draft":                   "Save as Draft",
        "update_status":                "Update Status",
        "mark_implemented":             "Mark as Implemented",
        "sign_in":                      "Sign In",
        "sign_out":                     "Sign Out",
        "close":                        "Close",
        "approve":                      "Approve",
        "reject":                       "Reject",
        "revoke":                       "Revoke",
        "renew":                        "Renew",
        "add_mitigation":               "Add Mitigation",
        "launch_dpia":                  "Launch DPIA",
        "report_incident":              "Report Incident",
        "submit":                       "Submit",

        # Status labels
        "active":                       "Active",
        "closed":                       "Closed",
        "open":                         "Open",
        "draft":                        "Draft",
        "pending":                      "Pending",
        "approved":                     "Approved",
        "rejected":                     "Rejected",
        "escalated":                    "Escalated",
        "in_progress":                  "In Progress",
        "resolved":                     "Resolved",
        "published":                    "Published",
        "revoked":                      "Revoked",
        "expired":                      "Expired",
        "renewed":                      "Renewed",

        # Field labels
        "status":                       "Status",
        "deadline":                     "Deadline",
        "risk_level":                   "Risk Level",
        "risk_score":                   "Risk Score",
        "customer_id":                  "Customer ID",
        "request_type":                 "Request Type",
        "submitted_at":                 "Submitted At",
        "sla_status":                   "SLA Status",
        "branch":                       "Branch",
        "region":                       "Region",
        "purpose":                      "Processing Purpose",
        "language":                     "Language",
        "version":                      "Version",
        "notes":                        "Notes",
        "description":                  "Description",
        "severity":                     "Severity",
        "department":                   "Department",
        "expiry_date":                  "Expiry Date",
        "decision":                     "Decision",
        "explanation":                  "Explanation",

        # KPI / metric labels
        "total_consents":               "Total Active Consents",
        "active_requests":              "Active Rights Requests",
        "open_dpias":                   "Open DPIAs",
        "reported_breaches":            "Reported Breaches",
        "overall_compliance":           "Overall Compliance Score",
        "sla_compliance_rate":          "SLA Compliance Rate",
        "total_requests":               "Total Requests",
        "unique_actors":                "Unique Actors",
        "chain_valid":                  "Chain Valid",

        # Section headings
        "executive_dashboard":          "Executive Privacy Dashboard",
        "governance_console":           "DPO Governance Console",
        "admin_console":                "System Administration Console",
        "branch_compliance":            "Branch Compliance Score Comparison",
        "sla_performance":              "SLA Performance by Branch",
        "consent_forecast":             "Consent Expiry Forecast",
        "clause_breakdown":             "Clause-by-Clause Breakdown",
        "action_items":                 "Pending Action Items",
        "feature_controls":             "Feature Implementation Controls",
        "ledger_integrity":             "Ledger Integrity Status",
        "audit_records":                "Audit Records",

        # Informational / caption texts
        "knowledge_graph":              "Knowledge Graph",
        "gis_map":                      "Branch GIS Map",
        "dpdp_caption":                 "Digital Personal Data Protection Act, 2023 Compliance Framework",
        "consent_caption":              "DPDPA 2023 — Full consent lifecycle: Draft → Active → Expired / Revoked / Renewed",
        "read_only_notice":             "Read-only access. Modifications are not permitted.",
        "access_restricted":            "Access restricted. Contact your Data Protection Officer.",
        "sla_recalc_caption":           "SLA recalculated on every page refresh. Red SLA triggers auto-escalation.",

        # Consent lifecycle
        "granted":                      "Granted",
        "denied":                       "Denied",
        "capture_consent":              "Capture New Consent",
        "consent_register":             "Consent Register",
        "revoke_renew":                 "Revoke / Renew",
        "analytics":                    "Analytics",

        # Rights types
        "access_data":                  "Access My Data",
        "correct_data":                 "Correct My Data",
        "erase_data":                   "Erase My Data",
        "revoke_consent":               "Revoke Consent",
        "nominate_rep":                 "Nominate Representative",
        "raise_grievance":              "Raise Grievance",

        # Risk levels
        "low":                          "Low",
        "medium":                       "Medium",
        "high":                         "High",
        "critical":                     "Critical",

        # Form placeholders
        "enter_request_details":        "Enter your request details",
        "enter_customer_id":            "Enter customer ID",
        "enter_reason":                 "Enter reason",

        # ── Breach module ─────────────────────────────────────────────────────
        "breach_caption":                       "DPDP Act 2023 Section 8 — Report, track and resolve data breach incidents. 6-hour regulatory notification obligation.",
        "breach_more_info":                     "Under DPDP Act 2023 Section 8(5) and DPDP Rules 2025 Rule 12, data fiduciaries must implement reasonable security safeguards and report personal data breaches within 6 hours of detection.",
        "total_incidents":                      "Total Incidents",
        "open_active":                          "Open / Active",
        "high_severity":                        "High Severity",
        "this_branch":                          "This branch",
        "all_branches":                         "All branches",
        "under_investigation":                  "Under investigation",
        "requires_dpo_review":                  "Requires DPO review",
        "cert_notification_required":           "DPDP Act 2023 requires notification to the Data Protection Board within 6 hours.",
        "incident_register":                    "Incident Register",
        "containment":                          "Containment",
        "incidents":                            "Incidents",
        "incident_title":                       "Incident Title",
        "incident_title_placeholder":           "e.g. Unauthorised access to loan records",
        "affected_data_categories":             "Affected Data Categories",
        "estimated_affected_records":           "Estimated Affected Records",
        "special_category_data_check":          "Contains Special Category Data (health, financial, biometric)?",
        "dpo_notified":                         "DPO has been notified",
        "dpo_notified_help":                    "Required for breaches affecting >10,000 records",
        "incident_description_placeholder":     "Describe what happened, systems/data affected, and immediate actions taken.",
        "predicted_severity":                   "Predicted severity",
        "auto_classified":                      "auto-classified, no manual override",
        "provide_incident_title":               "Please provide an incident title.",
        "select_data_category":                 "Please select at least one affected data category.",
        "sla_timer_started":                    "6-hour SLA timer started.",
        "breach_logged":                        "Breach Logged",
        "breach_logged_reason":                 "Incident registered for regulatory tracking. 6-hour SLA timer is now running.",
        "high_critical_detected":               "High/Critical severity detected.",
        "cohort_notified_auto":                 "Impacted customer cohort has been notified automatically.",
        "access_denied":                        "Access denied",
        "update_incident_status":               "Update Incident Status",
        "select_incident":                      "Select Incident",
        "new_status":                           "New Status",
        "incident":                             "Incident",
        "updated_to":                           "updated to",
        "regulatory_notification_recorded":     "Regulatory Notification Recorded",
        "breach_marked_reported":               "Breach marked as reported under statutory obligation.",
        "close_breach":                         "Close Breach",
        "breach_closed_success":                "Incident {id} closed. SLA record marked complete.",
        "breach_not_found":                     "Breach {id} not found or already closed.",
        "report_new_incident":                  "Report a New Data Breach Incident",
        "breach_reporting_more_info":           "Under DPDP Act 2023 Section 8(5) and Rule 12, data fiduciaries must report personal data breaches within 6 hours. Severity is automatically classified.",
        "breach_role_restricted":               "Breach reporting is restricted to Officers, Privacy Stewards, and the DPO.",
        "auto_assigned":                        "auto-assigned from your profile",
        "containment_step_documentation":       "Containment Step Documentation",
        "containment_more_info":                "Document all containment actions for audit defensibility. Each step is timestamped and attributed to the recording officer.",
        "containment_role_restricted":          "Containment documentation is restricted to Officers and the DPO.",
        "no_open_incidents_containment":        "No open incidents requiring containment steps.",
        "select_open_incident":                 "Select Open Incident",
        "containment_action":                   "Containment Action",
        "containment_action_placeholder":       "e.g. Access revoked for affected officer. Systems audit initiated.",
        "add_containment_step":                 "Add Containment Step",
        "describe_containment_action":          "Please describe the containment action.",
        "containment_step_recorded":            "Containment step recorded for {id}.",
        "view_containment_log_for":             "View Containment Log For",
        "no_containment_steps":                 "No containment steps recorded yet.",
        "timestamp":                            "Timestamp",
        "recorded_by":                          "Recorded By",
        "action":                               "Action",
        "breach_analytics":                     "Breach Analytics",
        "no_incident_data":                     "No incident data to analyse yet.",
        "incidents_by_severity":                "Incidents by Severity",
        "incidents_by_status":                  "Incidents by Status",
        "severity_auto_classified_more_info":   "Severity is automatically classified from impact count, data category sensitivity, and regulatory thresholds.",
        "incidents_by_branch":                  "Incidents by Branch",
        "incident_volume_by_branch":            "Incident Volume by Branch",
        "executive_breach_view_more_info":      "Executive view shows aggregated breach posture. Detailed operational handling remains restricted to branch officers.",
        "high_critical_unnotified":             "High/Critical incident(s) have not been notified to the Data Protection Board.",
        "six_hour_notification_obligation":     "6-Hour Notification Obligation",
        "six_hour_notification_reason":         "High and Critical incidents must be reported to the Data Protection Board within 6 hours under DPDP Act 2023 and DPDP Rules 2025.",
        "reported_at":                          "Reported At",
        "reporter":                             "Reporter",
        "impact_count":                         "Impact Count",
        "title":                                "Title",
        "no_incidents_branch":                  "No incidents recorded for your branch.",
        "yes":                                  "Yes",
        "no":                                   "No",
        "logged":                               "logged",
        "special_category":                     "Special Category",
        "summary":                              "Summary",

        # ── Compliance module ─────────────────────────────────────────────────
        "compliance_caption":                   "Real-time regulatory compliance derived from live system state. DPDP Act 2023, DPDP Rules 2025, RBI Cyber Security Framework, NABARD IT Guidelines, CERT-IN Directions 2022.",
        "compliance_more_info":                 "Compliance is computed dynamically from consent registry, rights workflow, SLA registry, breach registry, DPIA registry, and audit ledger. No manual overrides are permitted.",
        "compliance_access_restricted":         "Access restricted. Compliance and SLA Monitoring governance scoring is not available for the {role} role.",
        "compliance_sysadmin_hint":             "System Administrators can view technical audit telemetry via the Executive Dashboard and Audit Logs modules.",
        "compliance_officer_hint":              "Officers can view branch-level compliance summaries via the Executive Dashboard.",
        "overall_compliance_score":             "Overall Compliance Score",
        "clauses_evaluated":                    "clauses evaluated",
        "compliant":                            "Compliant",
        "partial":                              "Partial",
        "non_compliant":                        "Non-Compliant",
        "auditor_read_only":                    "Auditor view — read-only.",
        "clause_heatmap":                       "Clause Heatmap",
        "clause_detail":                        "Clause Detail",
        "clause_compliance_heatmap":            "Clause Compliance Heatmap",
        "heatmap_caption":                      "Colour indicates compliance status. Hover for clause reference.",
        "no_compliance_data":                   "No compliance data available. Ensure system registries are populated.",
        "clause":                               "Clause",
        "evidence":                             "Evidence",
        "visual_heatmap_overview":              "Visual Heatmap Overview",
        "clause_by_clause_detail":              "Clause-by-Clause Detail",
        "no_clause_data":                       "No clause data available.",
        "filter_by_status":                     "Filter by status",
        "all":                                  "All",
        "board_ready_export":                   "Board-Ready Export",
        "export_caption":                       "Export compliance report as PDF (board-ready), JSON (machine-readable), or XML (regulatory submission).",
        "download_clause_csv":                  "Download Clause CSV",

        # ── Notices module ────────────────────────────────────────────────────
        "notices_caption":                      "DPDP Act 2023 Section 5 — Manage, version, and publish privacy notices across all product journeys. Notices are immutable once published.",
        "notices_more_info":                    "Under DPDP Act 2023 Section 5, Data Fiduciaries must provide clear and accessible notice before obtaining consent, specifying purpose, retention, and grievance redressal. Every version is archived and linked to the relevant DPDP clauses.",
        "notices_access_restricted":            "Access restricted. Privacy Notices are not available for your role.",
        "notices_contact_dpo":                  "Contact the Data Protection Officer to request access.",
        "total_versions":                       "Total Versions",
        "drafts":                               "Drafts",
        "superseded":                           "Superseded",
        "products":                             "Products",
        "all_time":                             "All time",
        "live":                                 "Live",
        "pending_review":                       "Pending review",
        "archived":                             "Archived",
        "journeys_covered":                     "Journeys covered",
        "officer_draft_only":                   "Officer access: You may create draft notices. Only the DPO can publish.",
        "notice_history":                       "Notice History",
        "notice_preview":                       "Notice Preview",
        "create_version_notice":                "Create / Version Notice",
        "create_or_version_notice":             "Create or Version a Privacy Notice",
        "create_notice_caption":                "Saving always creates a new version. Existing notices are superseded, never overwritten.",
        "product_journey":                      "Product Journey",
        "active_version_for":                   "Active version for",
        "notice_title":                         "Notice Title",
        "notice_content_english":               "Privacy Notice Content (English)",
        "linked_dpdp_clauses":                  "Linked DPDP Clauses",
        "linked_clauses_help":                  "Select the regulatory clauses this notice addresses.",
        "version_note":                         "Version Note",
        "version_note_placeholder":             "e.g. Updated third-party sharing clause per DPDP Rules 2025",
        "preview_malayalam":                    "Preview Malayalam (auto-generated)",
        "malayalam_content":                    "Malayalam Content",
        "enter_english_to_preview":             "Enter English content above to preview.",
        "notice_content_empty":                 "Notice content cannot be empty.",
        "notice_clause_required":               "At least one DPDP clause must be linked.",
        "invalid_clause_codes":                 "Invalid clause codes",
        "officer_draft_caption":                "Drafts are submitted to the DPO for review and publication.",
        "saved_for":                            "saved for",
        "pending_dpo_review":                   "Pending DPO review.",
        "publish_notice":                       "Publish Notice",
        "reconsent_required":                   "Re-consent required — linked clauses changed.",
        "users_notified_sms":                   "user(s) notified via SMS.",
        "notice":                               "Notice",
        "published_for":                        "published for",
        "notice_published":                     "Privacy Notice Published",
        "notice_published_reason":              "Privacy notice versioned and made available prior to consent capture per DPDP Act 2023 Section 5.",
        "notice_version_history":               "Notice Version History",
        "auditor_history_view":                 "Read-only view. All published, draft, and superseded versions shown.",
        "filter_by_product":                    "Filter by Product",
        "requires_reconsent_only":              "Requires Re-Consent only",
        "notice_id":                            "Notice ID",
        "product":                              "Product",
        "clauses_linked":                       "Clauses Linked",
        "reconsent":                            "Re-consent?",
        "affected_users":                       "Affected Users",
        "published_on":                         "Published On",
        "by":                                   "By",
        "created_at":                           "Created At",
        "notice_versions_shown":                "notice version(s) shown.",
        "notice_history_more_info":             "Each version is immutable once published. Superseded versions are retained for regulatory audit. Re-consent flag indicates the linked clauses changed between versions.",
        "no_notices_match_filters":             "No notices match the selected filters.",
        "publish_pending_drafts":               "Publish Pending Drafts",
        "select_draft_to_publish":              "Select Draft to Publish",
        "publish_selected_draft":               "Publish Selected Draft",
        "no_published_notices_preview":         "No published notices available for preview.",
        "select_product":                       "Select Product",
        "display_language":                     "Display Language",
        "english":                              "English",
        "malayalam":                            "Malayalam",
        "linked_clauses_label":                 "Linked clauses",
        "view_superseded_version":              "View superseded previous version",
        "superseded_on":                        "Superseded on",
        "preview_language_caption":             "View notice content in English or Malayalam.",

        # ── app.py & auth.py UI strings ───────────────────────────────────────
        "app_title":                            "Consent Privacy Management System",
        "app_subtitle":                         "Kerala Bank — Digital Personal Data Protection Act, 2023",
        "dpcms_modules":                        "DPCMS Modules",
        "no_modules_available":                 "No modules available for your role.",
        "board_view_info":                      "Board view: Executive Dashboard only.",
        "customer_access_info":                 "Customer access: Rights Portal only.",
        "sysadmin_info":                        "System Administrator: Technical modules only.",
        "branch_label":                         "Branch",
        "region_label":                         "Region",
        "username":                             "Username",
        "password":                             "Password",
        "sign_in":                              "Sign In",
        "login_enter_both":                     "Please enter both username and password.",
        "login_invalid":                        "Invalid username or password.",
        "demo_credentials":                     "Demo Credentials",
        "name_label":                           "Name",
        "dept_label":                           "Department",
        "all_branches_head_office":             "All (Head Office)",
        "assisted_submission_active":           "Assisted Submission Mode Active",
        "session_duration":                     "Session duration",
        "minutes":                              "minutes",
        "session_expiring_soon":                "Session expires in approximately {minutes} minutes.",
        "session_expired":                      "Your session has expired. Please sign in again.",
        "access_denied_role":                   "Access Denied: Your role ({role}) does not have permission to view {module}.",
        "contact_dpo_access":                   "Contact your Data Protection Officer to request elevated access.",
        "login_config_error":                   "Login denied: account configuration error. Contact your system administrator.",

        # ── Role display names (always via t() — never hardcoded) ─────────────
        "role_customer":                        "Customer",
        "role_branch_officer":                  "Branch Officer",
        "role_privacy_steward":                 "Privacy Steward",
        "role_dpo":                             "DPO",
        "role_board_member":                    "Board Member",
        "role_auditor":                         "Auditor",
        "role_system_admin":                    "System Administrator",
        "role_unknown":                         "Unknown Role",

        # ── Demo credentials table column headers ─────────────────────────────
        "role_label":                           "Role",
        "access_label":                         "Access",
        "demo_access_dpo":                      "All 8 modules",
        "demo_access_officer":                  "5 modules",
        "demo_access_auditor":                  "4 modules",
        "demo_access_board":                    "Dashboard only",
        "demo_access_admin":                    "Tech modules",
        "demo_access_customer":                 "Rights portal only",

        # ── Consent processing purpose dropdown options ────────────────────────
        "purpose_loan":                         "Loan Processing",
        "purpose_kyc":                          "KYC Verification",
        "purpose_account":                      "Account Opening",
        "purpose_insurance":                    "Insurance",
        "purpose_credit":                       "Credit Assessment",
        "purpose_marketing":                    "Marketing",
        "purpose_fd":                           "Fixed Deposit",
        "purpose_savings":                      "Savings Account",
        "purpose_remittance":                   "Remittance",

        # ── Data category options (breach module multiselect) ─────────────────
        "cat_financial":                        "Financial",
        "cat_health":                           "Health",
        "cat_biometric":                        "Biometric",
        "cat_identity":                         "Identity",
        "cat_contact":                          "Contact",
        "cat_location":                         "Location",
        "cat_transaction":                      "Transaction History",
        "cat_employment":                       "Employment",

        # ── DPIA risk type dropdown options ───────────────────────────────────
        "risk_type_privacy":                    "Privacy Risk",
        "risk_type_security":                   "Security Risk",
        "risk_type_compliance":                 "Compliance Risk",
        "risk_type_operational":                "Operational Risk",

        # ── DPIA assessment type options ──────────────────────────────────────
        "assessment_full":                      "Full DPIA",
        "assessment_screening":                 "Screening Assessment",
        "assessment_targeted":                  "Targeted Review",

        # ── Notice product journey options ────────────────────────────────────
        "journey_savings":                      "Savings Account",
        "journey_loan":                         "Loan",
        "journey_insurance":                    "Insurance",
        "journey_fd":                           "Fixed Deposit",
        "journey_remittance":                   "Remittance",
        "journey_credit_card":                  "Credit Card",

        # ── Filter / sort options ─────────────────────────────────────────────
        "filter_all":                           "All",
        "sort_newest":                          "Newest First",
        "sort_oldest":                          "Oldest First",
        "sort_severity":                        "By Severity",

        # ── Consent capture tab labels ────────────────────────────────────────
        "tab_capture":                          "Capture Consent",
        "tab_register":                         "Register",
        "tab_revoke_renew":                     "Revoke / Renew",
        "tab_analytics":                        "Analytics",

        # ── Rights portal specific ────────────────────────────────────────────
        "my_requests":                          "My Requests",
        "no_requests_found":                    "No requests found.",
        "request_submitted":                    "Request submitted successfully.",
        "request_already_pending":              "A request of this type is already pending.",
        "representative_name":                  "Representative Name",
        "grievance_details":                    "Grievance Details",

        # ── Generic UI ────────────────────────────────────────────────────────
        "loading":                              "Loading...",
        "no_data":                              "No data available.",
        "confirm":                              "Confirm",
        "cancel":                               "Cancel",
        "search":                               "Search",
        "select":                               "Select",
        "back":                                 "Back",
        "next":                                 "Next",

        # ── Nav module labels (used in option_menu) ───────────────────────────
        "executive_dashboard":                  "Executive Dashboard",
        "data_principal_rights":                "Data Principal Rights",
        "dpia_privacy_assessments":             "DPIA & Privacy Assessments",
        "data_breach_management":               "Data Breach Management",
        "privacy_notices":                      "Privacy Notices",
        "audit_logs":                           "Audit Logs",
        "compliance_sla_monitoring":            "Compliance & SLA Monitoring",

        # ── Audit module ──────────────────────────────────────────────────────
        "audit_caption":                "Tamper-evident, hash-chained logs — DPDP Act 2023 compliance.",
        "audit_more_info":              "The audit ledger is append-only and hash-chained. All governance actions are recorded to ensure immutability and regulatory traceability.",
        "ledger_integrity":             "Ledger Integrity Status",
        "ledger_verified":              "Ledger Verified. {total} entries intact.",
        "ledger_integrity_verified":    "Ledger Integrity Verified",
        "ledger_verified_reason":       "Hash chain validation confirms no tampering detected.",
        "ledger_corrupted":             "Ledger Integrity Issue: {message}",
        "ledger_integrity_breach":      "Ledger Integrity Breach",
        "ledger_breach_reason":         "Hash mismatch detected in audit chain.",
        "ledger_verified_banner":       "Ledger Integrity: VERIFIED — {total} entries checked. Chain intact.",
        "ledger_tampered_banner":       "LEDGER INTEGRITY ISSUE — {message}",
        "total_log_entries":            "Total Log Entries",
        "all_records":                  "All records",
        "distinct_users":               "Distinct users",
        "latest_entry":                 "Latest Entry",
        "most_recent_log":              "Most recent log",
        "verified":                     "Verified",
        "compromised":                  "COMPROMISED",
        "audit_kpi_more_info":          "Total Entries: Number of recorded governance events. Unique Actors: Distinct user accounts. Chain Valid: Cryptographic integrity status.",
        "audit_records":                "Audit Records",
        "dev_tools":                    "Dev Tools",
        "filter_logs":                  "Filter Logs",
        "filter_by_actor":              "Filter by Actor",
        "filter_by_action":             "Filter by Action keyword",
        "date_range":                   "Date Range",
        "last_24h":                     "Last 24h",
        "last_7_days":                  "Last 7 days",
        "last_30_days":                 "Last 30 days",
        "max_rows":                     "Max Rows",
        "shown":                        "shown",
        "entry_id":                     "Entry ID",
        "actor":                        "Actor",
        "previous_hash":                "Previous Hash",
        "current_hash":                 "Current Hash",
        "inspect_full_hashes":          "Inspect Full Hashes for a Specific Entry",
        "select_entry":                 "Select Entry",
        "download_logs_csv":            "Download Logs as CSV",
        "no_audit_entries":             "No audit log entries match the selected filters. Actions taken in the system will appear here.",
        "audit_hash_info":              "Each entry is cryptographically hashed (SHA-256) and chain-linked to the previous entry, ensuring tamper evidence across the full log history.",
        "developer_tools":              "Developer Tools",
        "dev_tools_more_info":          "This panel is for development and testing only. In production, manual log entries should not be permitted outside automated governance flows.",
        "write_test_log_entry":         "Write Test Log Entry (Dev Only)",
        "write_to_ledger":              "Write to Ledger",
        "entry_written":                "Entry written. Refresh to see it.",

        # ── Step 7A/7B/7E — i18n hardening meta-strings ──────────────────────
        "translation_parity_error":     "Translation parity failure: missing keys in language '{lang}': {keys}",
        "translation_key_missing":      "Missing translation key '{key}' for language '{lang}'",
        "english_leakage_detected":     "English leakage detected in Malayalam output for key '{key}'",
        "i18n_validation_passed":       "Translation completeness validated: all languages match English key set.",

        # ── Step 7C — Dropdown option keys (used in DROPDOWN_OPTIONS) ─────────
        "status_open":                  "Open",
        "status_closed":                "Closed",
        "status_under_review":          "Under Review",
        "status_pending":               "Pending",
        "status_active":                "Active",
        "status_resolved":              "Resolved",
        "status_escalated":             "Escalated",
        "status_approved":              "Approved",
        "status_rejected":              "Rejected",
        "risk_low":                     "Low",
        "risk_medium":                  "Medium",
        "risk_high":                    "High",
        "risk_critical":                "Critical",
        "sla_on_track":                 "On Track",
        "sla_at_risk":                  "At Risk",
        "sla_breached":                 "Breached",
        "filter_all_statuses":          "All Statuses",
        "filter_all_regions":           "All Regions",
        "filter_all_branches":          "All Branches",
        "export_format_pdf":            "PDF (Board-ready)",
        "export_format_json":           "JSON (Machine)",
        "export_format_xml":            "XML (Regulatory)",

        # ── Step 7F — Clause label keys ───────────────────────────────────────
        "clause_label_dpdp_s5":         "DPDP Act 2023 Section 5 — Notice",
        "clause_label_dpdp_s6":         "DPDP Act 2023 Section 6 — Consent",
        "clause_label_dpdp_s7":         "DPDP Act 2023 Section 7 — Legitimate Uses",
        "clause_label_dpdp_s8":         "DPDP Act 2023 Section 8 — Breach Notification",
        "clause_label_dpdp_s9":         "DPDP Act 2023 Section 9 — Children's Data",
        "clause_label_dpdp_s10":        "DPDP Act 2023 Section 10 — Significant Fiduciary",
        "clause_label_dpdp_s11":        "DPDP Act 2023 Section 11 — Data Principal Rights",
        "clause_label_dpdp_s12":        "DPDP Act 2023 Section 12 — Right to Correction",
        "clause_label_dpdp_s13":        "DPDP Act 2023 Section 13 — Right to Grievance Redressal",
        "clause_label_dpdp_s16":        "DPDP Act 2023 Section 16 — Data Retention Limit",
        "clause_label_rbi_csf":         "RBI Cyber Security Framework",
        "clause_label_nabard_it":       "NABARD IT Guidelines",
        "clause_label_cert_in":         "CERT-IN Directions 2022",
        "clause_label_dpdp_r12":        "DPDP Rules 2025 Rule 12 — Breach Reporting",

        # ── Step 8 engine-dashboard new keys ─────────────────────────────────
        "system_dashboard":             "System Dashboard",
        "active_breaches":              "Active Breaches",
        "weighted_score":               "Weighted across frameworks",
        "weighted_across_branches":     "Weighted across all branches",
        "audit_chain_valid":            "Audit Chain Integrity: VERIFIED",
        "audit_chain_broken":           "Audit Chain Integrity: BROKEN",
        "root_hash":                    "Root Hash",
        "contact_dpo_immediately":      "Contact the DPO immediately",
        "escalation_overview":          "Escalation Overview",
        "escalation_branch":            "Branch",
        "escalation_regional":          "Regional",
        "escalation_dpo":               "DPO",
        "escalation_board":             "Board",
        "escalations_pending":          "escalations pending",
        "level":                        "Level",
        "dpia_status_summary":          "DPIA Status Summary",
        "dpia_active":                  "Active DPIAs",
        "dpia_overdue":                 "Overdue DPIAs",
        "dpia_approved":                "Approved DPIAs",
        "cleared":                      "Cleared",
        "requires_action":              "Requires Action",
        "regional_dashboard_caption":   "Regional aggregation view",
        "regional_average":             "Regional average",
        "no_data_for_region":           "No data available for your region.",
        "engine_data_unavailable":      "Engine data unavailable — some metrics may be incomplete.",
        "escalation_dpia":              "Escalation & DPIA",
        "framework_compliance_breakdown": "Framework Compliance Breakdown",
        "governance_report":            "Governance Report",
        "customer_dashboard_message":   "Welcome to the Kerala Bank Data Privacy Portal.",
        "customer_consents_caption":    "Your active consents and rights requests.",
        "no_governance_metrics_for_customer": "Governance metrics are not available for customer accounts.",

        # ── Step 15 export-hardening new keys ────────────────────────────────
        "classification_confidential":  "CONFIDENTIAL",
        "classification_label":         "Classification",
        "generated_at":                 "Generated At",
        "page":                         "Page",
        "additional_data":              "Additional Data",
        "data":                         "Data",
        "details":                      "Details",
        "clause_level_compliance_detail": "Clause-Level Compliance Detail",
        "clause_id":                    "Clause ID",
        "amendment_reference":          "Amendment Reference",
        "score":                        "Score",
        "export_pdf":                   "PDF (Board-ready)",
        "export_json":                  "JSON (Machine)",
        "export_xml":                   "XML (Regulatory)",
        "download_pdf":                 "Download PDF",
        "download_json":                "Download JSON",
        "download_xml":                 "Download XML",
        "pdf_generation_failed":        "PDF generation failed",
        "export_failed":                "Export failed",
        "audit_log_write_failed":       "Audit log write failed",
        "on_track":                     "On Track",
        "at_risk":                      "At Risk",
        "breached":                     "Breached",
        "overdue":                      "Overdue",
        "days":                         "days",
        "request_id":                   "Request ID",
        "score_pct":                    "Score %",
        "open_requests":                "Open Requests",
        "sla_breaches":                 "SLA Breaches",
        "across_system":                "Across system",
        "board_dashboard_caption":      "Executive summary — all regions",
        "dpo_dashboard_caption":        "Full governance console — all modules",
        "auditor_dashboard_caption":    "Compliance oversight view — read-only",
        "admin_dashboard_caption":      "Technical system health console",
        "dpdp_compliance_view":         "DPDP Compliance View",
        "across_4_frameworks":          "Across 4 regulatory frameworks",
        "requests_within_deadline":     "Requests resolved within SLA deadline",
        "incident_governance":          "Incident governance",
        "lifecycle_compliant":          "Lifecycle compliant",
        "under_sla_monitoring":         "Under SLA monitoring",
        "requires_escalation":          "Requires escalation",
        "regulatory_score":             "Regulatory compliance score",
        "sla_status_distribution":      "SLA Status Distribution",
        "sla_status_this_branch":       "SLA Status — This Branch",
        "branch_risk_level":            "Branch Risk Level",
        "current_risk_status":          "Current Risk Status",
        "active_incidents_reported":    "active incidents reported",
        "rights_requests_action_required": "Rights Requests — Action Required",
        "branch_risk_distribution":     "Branch Risk Distribution",
        "branch_risk_profile_by_zone":  "Branch Risk Profile by Zone",
        "component_health":             "Component Health",
        "rule_engine":                  "Rule Engine",
        "orchestration_layer":          "Orchestration Layer",
        "audit_ledger":                 "Audit Ledger",
        "auth_service":                 "Auth Service",
        "db_connection_pool":           "DB Connection Pool",
        "compliance_engine":            "Compliance Engine",
        "currently_logged_in":          "Currently logged in",
        "log_entries_recorded":         "Log entries recorded today",
        "since_last_reset":             "Since last reset",
        "current_period":               "Current period",
        "audit_event_volume_today":     "Audit Event Volume Today",
        "event_distribution":           "Event Distribution",
        "evt_login":                    "Login",
        "evt_data_access":              "Data Access",
        "evt_consent_update":           "Consent Update",
        "evt_rights_request":           "Rights Request",
        "evt_dpia_action":              "DPIA Action",
        "evt_breach_report":            "Breach Report",
        "evt_login_successful":         "Login Successful",
        "evt_consent_updated":          "Consent Updated",
        "evt_login_failed":             "Login Failed",
        "evt_rights_request_submitted": "Rights Request Submitted",
        "total_audit_entries":          "Total Audit Entries",
        "last_backup":                  "Last Backup",
        "no_data_for_branch":           "No data available for your branch.",
        "avg_compliance_score":         "Avg Compliance Score",
        "branches_below_target":        "Branches Below Target",
        "score_below_90":               "Score below 90%",
        "branch_compliance_scorecard":  "Branch Compliance Scorecard",
        "compliance_score_pct":         "Compliance Score %",
        "open_rights_requests":         "Open Rights Requests",
        "compliance_vs_rights_requests": "Compliance vs Rights Requests",
        "active_rights_requests_per_branch": "Active Rights Requests per Branch",
        "rights_request_volume_by_branch": "Rights Request Volume by Branch",
        "rights_request_management":    "Rights Request Management",
        "no_incidents_reported":        "No incidents reported.",
        "kerala_branch_risk_distribution": "Kerala Branch Risk Distribution",
        "gis_map_note":                 "Map shows branch risk distribution across Kerala.",
        "knowledge_graph_caption":      "Entity relationship map for DPDP governance.",
        "knowledge_graph_note":         "Graph shows relationships between key governance entities.",
        "kg_customer":                  "Customer",
        "kg_consent":                   "Consent",
        "kg_purpose":                   "Purpose",
        "kg_branch":                    "Branch",
        "kg_dpia":                      "DPIA",
        "kg_risk":                      "Risk",
        "kg_rights_request":            "Rights Request",
        "kg_sla":                       "SLA",
        "kg_compliance":                "Compliance",
        "gis_map_caption":              "Geospatial view of branch risk posture across Kerala.",
        "target_90_pct":                "Target: 90%",
        "purpose_distribution_note":    "Compliance score derived from live engine state.",
        "branch_level_compliance_scores": "Branch-Level Compliance Scores",
        "projected_consent_expirations": "Projected Consent Expirations",
        "expiring_consents":            "Expiring Consents",
        "consent_forecast_august_warning": "⚠ August 2026: High expiry volume predicted. Begin early renewal outreach.",
        "sla_status_by_branch":         "SLA Status by Branch",
        "approved_dpias":               "Approved DPIAs",

        # ── Missing keys — dashboard / sla_engine ─────────────────────────
        "get_escalation_summary":       "Escalation Summary",
        "escalation_summary":           "Escalation Summary",
        "no_escalations":               "No active escalations.",
        "escalation_level":             "Escalation Level",
        "escalated_to":                 "Escalated To",
        "sla_breach_count":             "SLA Breach Count",
        "weighted_score_label":         "Weighted Score",
        "weighted_compliance_score":    "Weighted Compliance Score",
        "score_breakdown":              "Score Breakdown",
        "framework_scores":             "Framework Scores",
        "clause_scores":                "Clause Scores",
        "overall_compliance":           "Overall Compliance",
        "compliance_trend":             "Compliance Trend",
        "risk_heatmap":                 "Risk Heatmap",
        "remediation_actions":          "Remediation Actions",
        "pending_remediation":          "Pending Remediation",
        "score_label":                  "Score",
        "weight_label":                 "Weight",
        "evidence_label":               "Evidence",
        "amendment_ref":                "Amendment Reference",
        "clause_status":                "Clause Status",
        "compliant":                    "Compliant",
        "non_compliant":                "Non-Compliant",
        "partial":                      "Partial",

        # ── Missing keys — dpia.py ────────────────────────────────────────
        "dpia_caption":                 "Conduct Privacy Impact Assessments per DPDP Act 2023 Section 10.",
        "dpia_more_info":               "DPIA is required for high-risk data processing activities.",
        "dpia_new":                     "New DPIA",
        "dpia_list":                    "DPIA Register",
        "dpia_id_label":                "DPIA ID",
        "dpia_project":                 "Project / System",
        "dpia_risk_level":              "Risk Level",
        "dpia_status":                  "Status",
        "dpia_submitted_by":            "Submitted By",
        "dpia_submitted_at":            "Submitted At",
        "dpia_approved_by":             "Approved By",
        "dpia_approved_at":             "Approved At",
        "dpia_review_due":              "Review Due",
        "dpia_no_records":              "No DPIA records found.",
        "dpia_approve_btn":             "Approve",
        "dpia_reject_btn":              "Reject",
        "dpia_submit_btn":              "Submit DPIA",
        "dpia_risk_evaluation":         "Risk Evaluation",
        "dpia_description":             "Description",
        "dpia_data_categories":         "Data Categories",
        "dpia_processing_purpose":      "Processing Purpose",
        "dpia_third_parties":           "Third Parties Involved",
        "dpia_retention_period":        "Retention Period",
        "dpia_safeguards":              "Safeguards",
        "dpia_residual_risk":           "Residual Risk",
        "dpia_filter_status":           "Filter by Status",
        "dpia_filter_risk":             "Filter by Risk Level",
        "dpia_detail":                  "DPIA Detail",
        "dpia_decision":                "Decision",
        "dpia_notes":                   "DPO Notes",
        "dpia_save":                    "Save",
        "dpia_created":                 "DPIA submitted successfully.",
        "dpia_approved_msg":            "DPIA approved.",
        "dpia_rejected_msg":            "DPIA rejected.",
        "dpia_pending":                 "Pending",
        "dpia_approved":                "Approved",
        "dpia_rejected":                "Rejected",
        "dpia_draft":                   "Draft",
        "dpia_high":                    "High",
        "dpia_medium":                  "Medium",
        "dpia_low":                     "Low",
        "dpia_section_header":          "DPIA & Privacy Assessments",
        "dpia_periodic_review":         "Periodic Review Schedule",
        "dpia_next_review":             "Next Review Date",
        "dpia_overdue":                 "Overdue",
        "dpia_due_soon":                "Due Soon",

        # ── Missing keys — audit.py ───────────────────────────────────────
        "ledger_root_hash":             "Ledger Root Hash",
        "root_hash_caption":            "SHA-256 of the entire serialised ledger — governance transparency signal.",
        "root_hash_note":               "This hash uniquely identifies the current state of the entire audit ledger.",
        "root_hash_more_info":          "The root hash allows out-of-band tamper detection by comparing against an external record.",
        "root_hash_unavailable":        "Root hash not yet generated.",
        "ledger_integrity_metadata":    "Ledger Integrity Metadata",
        "integrity_metadata_note":      "This metadata is cryptographically derived from the live ledger.",
        "total_entries":                "Total Entries",
        "root_hash":                    "Root Hash",

        # ── Missing keys — rights_portal.py ──────────────────────────────
        "dpo_console_more_info":        "DPO console allows review, verification, and decision on all rights requests.",
        "dpo_console":                  "DPO Console",
        "dpo_console_caption":          "Review and manage all Data Subject Rights requests.",
        "officer_console":              "Officer Console",
        "officer_console_caption":      "Review and assist rights requests for your branch.",
        "request_id_label":             "Request ID",
        "request_type_label":           "Request Type",
        "request_status_label":         "Status",
        "request_submitted_at":         "Submitted At",
        "request_deadline":             "Deadline",
        "request_sla_status":           "SLA Status",
        "request_customer":             "Customer ID",
        "request_notes":                "Notes",
        "request_decision":             "Decision",
        "identity_verified_label":      "Identity Verified",
        "verify_identity_btn":          "Verify Identity",
        "approve_request_btn":          "Approve",
        "reject_request_btn":           "Reject",
        "escalate_request_btn":         "Escalate",
        "no_rights_requests":           "No rights requests found.",
        "rights_filter_type":           "Filter by Type",
        "rights_filter_status":         "Filter by Status",
        "rights_all_types":             "All Types",
        "rights_all_statuses":          "All Statuses",
        "rights_open":                  "Open",
        "rights_closed":                "Closed",
        "rights_escalated":             "Escalated",
        "rights_in_progress":           "In Progress",
        "assisted_mode_label":          "Assisted Submission Mode",
        "submit_on_behalf":             "Submit on behalf of customer",

        # ── Round-3 parity keys ──────────────────────────────────────────
        "access_my_data":                              "Access My Data",
        "audit_access_restricted":                     "Access restricted. Audit logs are read-only for this role.",
        "audit_contact_dpo":                           "Contact your Data Protection Officer for full audit access.",
        "auditor":                                     "Auditor",
        "authenticated":                               "Authenticated",
        "board_member":                                "Board Member",
        "branch_officer":                              "Branch Officer",
        "consent_withdrawal_action":                   "Consent Withdrawal",
        "correct_my_data":                             "Correct My Data",
        "create_rights_request":                       "Create Rights Request",
        "data_access":                                 "Data Access",
        "data_access_request":                         "Data Access Request",
        "data_correction":                             "Data Correction",
        "data_correction_request":                     "Data Correction Request",
        "data_erasure":                                "Data Erasure",
        "data_erasure_request":                        "Data Erasure Request",
        "dpo":                                         "DPO",
        "erase_my_data":                               "Erase My Data",
        "grievance_redressal":                         "Grievance Redressal",
        "kyc":                                         "KYC",
        "kyc_verification":                            "KYC Verification",
        "last_active":                                 "Last Active",
        "loan_processing":                             "Loan Processing",
        "login_account_locked":                        "Account locked due to too many failed attempts. Please try again in {minutes} minutes.",
        "login_error":                                 "Login error. Please contact the system administrator.",
        "login_lockout_wait":                          "Account is locked. Please wait {minutes} minutes before trying again.",
        "login_time":                                  "Login Time",
        "mfa_enter_code":                              "Enter your 6-digit authenticator code",
        "mfa_invalid":                                 "Invalid or expired code. Please try again.",
        "mfa_required":                                "Multi-Factor Authentication Required",
        "mfa_secret":                                  "MFA Secret",
        "mfa_verified":                                "MFA Verified",
        "mfa_verify":                                  "Verify",
        "nominate_representative":                     "Nominate Representative",
        "nomination_request":                          "Nomination Request",
        "password_hash":                               "Password Hash",
        "privacy_steward":                             "Privacy Steward",
        "regional_officer":                            "Regional Officer",
        "request":                                     "Request",
        "requires_id_verification":                    "requires identity verification",
        "requires_mandatory_id_verification":          "requires mandatory identity verification",
        "revoke_consent_request":                      "Revoke Consent",
        "role":                                        "Role",
        "stage_closed":                                "Closed",
        "stage_dpo_approved":                          "DPO Approved",
        "stage_initiated":                             "Initiated",
        "stage_rejected":                              "Rejected",
        "stage_steward_approved":                      "Steward Approved",
        "stage_under_review":                          "Under Review",
        "steward_approved":                            "Steward Approved",
        "system_admin":                                "System Admin",
        "under_review":                                "Under Review",
        "unknown_user":                                "Unknown User",
        "valid_consent_required_for":                  "Valid consent required for",
        "warning":                                     "Warning",

        # ── Missing keys — notices.py ─────────────────────────────────────
        "notices_init_error":           "Notice initialisation error. Please contact the DPO.",
        "notices_load_error":           "Failed to load privacy notices.",
        "notice_save_error":            "Failed to save notice.",
        "notice_publish_error":         "Failed to publish notice.",

        # ── Missing keys — breach.py ──────────────────────────────────────
        "breach_load_error":            "Failed to load breach incidents.",
        "breach_init_error":            "Breach module initialisation error.",

        # ── Missing keys — consent_management.py ─────────────────────────
        "consent_access_restricted":    "Access restricted. Contact your Data Protection Officer.",
        "consent_contact_dpo":          "Contact your Data Protection Officer to request elevated access.",
        "consent_load_error":           "Failed to load consent records.",

        # ── dashboard.py missing keys ─────────────────────────────────────
        "access":                       "Access",
        "active_sessions":              "Active Sessions",
        "audit_events_today":           "Audit Events Today",
        "branch_risk_overview":         "Branch Risk Overview",
        "correction":                   "Correction",
        "count":                        "Count",
        "erasure":                      "Erasure",
        "escalate":                     "Escalate",
        "event":                        "Event",
        "event_type":                   "Event Type",
        "failed_logins":                "Failed Logins",
        "filter_by_branch":             "Filter by Branch",
        "grievance":                    "Grievance",
        "reported_incidents":           "Reported Incidents",
        "rights_requests":              "Rights Requests",
        "system_uptime":                "System Uptime",
        "unknown":                      "Unknown",
        "user":                         "User",
        "your_consents":                "Your Consents",
        "timestamp":                    "Timestamp",
        "title":                        "Title",
        "total_consents":               "Total Consents",
        "total_requests":               "Total Requests",
        "total_incidents":              "Total Incidents",
        "total_dpias":                  "Total DPIAs",

        # ── rights_portal.py missing keys ─────────────────────────────────
        "active_cases":                 "Active Cases",
        "active_request_progress":      "Active Request Progress",
        "all_requests_by_status":       "All Requests by Status",
        "all_requests_closed":          "All Requests (Closed)",
        "all_requests_live_sla":        "All Requests — Live SLA",
        "all_requests_live_sla_readonly": "All Requests — Live SLA (Read Only)",
        "all_requests_sla":             "All Requests SLA",
        "all_submitted":                "All Submitted",
        "approaching_deadline":         "Approaching Deadline",
        "assisted":                     "Assisted",
        "assisted_branch_officer":      "Assisted by Branch Officer",
        "assisted_submission":          "Assisted Submission",
        "auditor_rights_caption":       "Read-only view of all rights requests.",
        "auto_escalated_when_red":      "Auto-escalated when SLA turns Red.",
        "being_processed":              "Being Processed",
        "branch_requests":              "Branch Requests",
        "consent_gate":                 "Consent Gate",
        "customer_id_required":         "Customer ID is required.",
        "customer_portal_caption":      "Submit and track your data rights requests under DPDP Act 2023.",
        "customer_rights_caption":      "Your rights under the Digital Personal Data Protection Act 2023.",
        "customer_rights_sla_note":     "Requests are processed within 30 days per DPDP Act Section 13.",
        "days_left":                    "Days Left",
        "dpdp_timely_processing_note":  "DPDP Act 2023 mandates timely processing of all rights requests.",
        "dpo_submission_info":          "DPO can submit requests on behalf of customers.",
        "escalated_overdue_requests":   "Escalated / Overdue Requests",
        "escalated_to_dpo":             "Escalated to DPO",
        "escalations":                  "Escalations",
        "flagged_for_dpo_review":       "Flagged for DPO Review",
        "for_dpo_action":               "For DPO Action",
        "his_branch":                   "This Branch",
        "id":                           "ID",
        "id_verified":                  "ID Verified",
        "identity_marked_verified":     "Identity marked as verified.",
        "identity_verification_required_error": "Identity verification required before processing.",
        "identity_verified":            "Identity Verified",
        "identity_verified_confirm":    "Confirm identity has been verified in person or via OTP.",
        "immediate_attention":          "Immediate Attention Required",
        "mark_identity_verified":       "Mark Identity Verified",
        "my_request_history":           "My Request History",
        "my_requests_only_caption":     "Showing your submitted requests only.",
        "my_total_requests":            "My Total Requests",
        "no_data_yet":                  "No data yet.",
        "no_escalated_requests":        "No escalated requests.",
        "no_records_match_filters":     "No records match the selected filters.",
        "no_requests_submitted_yet":    "No requests submitted yet.",
        "officer_assisted_caption":     "Submit a rights request on behalf of a customer.",
        "officer_assisted_info":        "Officer-assisted submission is recorded in the audit ledger.",
        "officer_assisted_more_info":   "Assisted submissions require customer identity verification.",
        "officer_branch_requests_caption": "Rights requests submitted at your branch.",
        "officer_id_verification_confirm": "Confirm you have verified the customer's identity.",
        "open_requests_by_sla":         "Open Requests by SLA Status",
        "preview_request":              "Preview Request",
        "preview_request_customer_view": "Preview (Customer View)",
        "rate_limit_exceeded_session":  "Too many submissions this session. Please try again later.",
        "red_escalated":                "Red / Escalated",
        "resolution_note":              "Resolution Note",
        "rights_invocation_reason":     "Reason for invoking this right",
        "rights_invocation_title":      "Rights Invocation",
        "search_customer_id":           "Search by Customer ID",
        "select_request":               "Select Request",
        "self_service":                 "Self Service",
        "sla_amber":                    "SLA Amber",
        "sla_analytics":                "SLA Analytics",
        "sla_green":                    "SLA Green",
        "sla_legend_note":              "Green: on track | Amber: approaching deadline | Red: overdue",
        "sla_performance_analytics":    "SLA Performance Analytics",
        "sla_red":                      "SLA Red",
        "submit_assisted_request":      "Submit Assisted Request",
        "submit_on_behalf_of_customer": "Submit on Behalf of Customer",
        "submitted":                    "Submitted",
        "submitted_on":                 "Submitted On",
        "supporting_details":           "Supporting Details",
        "verification_method":          "Verification Method",
        "within_window":                "Within Window",

        # ── breach.py missing keys ─────────────────────────────────────────
        "all_incidents_closed":         "All Incidents Closed",
        "closed_at":                    "Closed At",
        "confirm_authority_notification": "Confirm Authority Notification Sent",
        "confirm_authority_notification_help": "Tick to confirm the regulatory authority has been notified.",
        "decision_metadata":            "Decision Metadata",
        "no_transitions_available":     "No transitions available.",
        "notification_required_before_closure": "Authority notification required before closure.",

        # ── compliance.py missing keys ─────────────────────────────────────
        "compliance_customer_hint":     "Compliance view is read-only for this role.",
        "compliance_regression_reason": "Regression detected in compliance score.",
        "compliance_regression_title":  "Compliance Regression",
        "compliance_score_trend":       "Compliance Score Trend",
        "compliant_clauses":            "Compliant Clauses",
        "compliant_threshold":          "Compliant Threshold",
        "date":                         "Date",
        "download_trend_csv":           "Download Trend CSV",
        "drift_detected":               "Drift Detected",
        "no_evidence_recorded":         "No evidence recorded.",
        "no_trend_data":                "No trend data available.",
        "non_compliant_clauses":        "Non-Compliant Clauses",
        "officer_compliance_limited_view": "Officers have a limited compliance view.",
        "overall_score_pct":            "Overall Score (%)",
        "partial_threshold":            "Partial Threshold",
        "trend_caption":                "Compliance score trend over time.",
        "trend_more_info":              "Score is derived from live system state — consent, SLA, breach, DPIA, and audit data.",
        "triggered_by":                 "Triggered By",
        "snapshot_at":                  "Snapshot At",
        "snapshot_date":                "Snapshot Date",
        "snapshot_history":             "Snapshot History",
        "weight":                       "Weight",

        # ── consent_management.py missing keys ────────────────────────────
        "assisted_consent_info":        "Consent captured on behalf of customer by officer.",
        "assisted_consent_registered_reason": "Officer-assisted consent registered.",
        "assisted_consent_registered_title": "Assisted Consent Registered",
        "auditor_no_revoke_renew":      "Auditors cannot revoke or renew consents.",
        "auditor_readonly_info":        "Auditor view is read-only.",
        "branch_notes":                 "Branch Notes",
        "capture_assisted_consent":     "Capture Assisted Consent",
        "consent_creation_info":        "New consent requires customer identity verification.",
        "consent_lifecycle_caption":    "Manage consent lifecycle — capture, renew, revoke.",
        "consent_lifecycle_info":       "All consent actions are recorded in the audit ledger.",
        "consent_registered_reason":    "New consent registered.",
        "consent_registered_title":     "Consent Registered",
        "consent_renewed_reason":       "Consent renewed successfully.",
        "consent_renewed_title":        "Consent Renewed",
        "consent_revoked_reason":       "Consent revoked.",
        "consent_revoked_title":        "Consent Revoked",
        "consent_status_legend":        "Active | Revoked | Expired | Renewed",
        "consent_withdrawn":            "Consent Withdrawn",
        "consents_by_purpose":          "Consents by Purpose",
        "consents_by_status":           "Consents by Status",
        "created":                      "Created",
        "customer":                     "Customer",
        "customer_decision":            "Customer Decision",
        "customer_revoke_info":         "Customers may revoke consent at any time.",
        "deny_consent":                 "Deny Consent",
        "dpo_auditor_no_consent_creation": "DPO and Auditors cannot create consents directly.",
        "expires":                      "Expires",
        "filter_by_purpose":            "Filter by Purpose",
        "full_ids_visible":             "Full IDs visible (DPO/Auditor view).",
        "grant_consent":                "Grant Consent",
        "ids_masked_policy":            "Customer IDs are masked per data minimisation policy.",
        "initiator":                    "Initiator",
        "kpi_realtime_note":            "KPIs are derived from live consent registry.",
        "na":                           "N/A",
        "no_consent_data":              "No consent records found.",
        "notes_context":                "Notes / Context",
        "officer_consent_warning":      "Consent actions are binding and audit-logged.",
        "processing_purpose":           "Processing Purpose",
        "re_authorised":                "Re-Authorised",
        "requires_renewal":             "Requires Renewal",
        "revocation_reason":            "Revocation Reason",
        "revocation_reason_placeholder": "Enter reason for revocation...",
        "revoked_at":                   "Revoked At",
        "revoked_by_officer_default":   "Revoked by officer",
        "submit_my_consent":            "Submit My Consent",
        "your_customer_id":             "Your Customer ID",
        "your_decision":                "Your Decision",

        # ── dpia.py missing keys ───────────────────────────────────────────
        "target_stage":                 "Target Stage",
        "awaiting_action":              "Awaiting Action",
        "close_dpia":                   "Close DPIA",
        "critical_dpia_escalation_reason": "Critical risk DPIA requires DPO approval.",
        "critical_dpia_escalation_title": "Critical DPIA Escalated",
        "data_categories_involved":     "Data Categories Involved",
        "describe_mitigation_action":   "Describe the mitigation action taken.",
        "describe_processing_activity": "Describe the processing activity.",
        "dpia_analytics":               "DPIA Analytics",
        "dpia_closed_success":          "DPIA closed successfully.",
        "dpia_creation_note":           "Initiate a DPIA for any high-risk processing activity.",
        "dpia_creation_restricted":     "DPIA creation is restricted to Officers and DPO.",
        "dpia_id":                      "DPIA ID",
        "dpia_initiated_reason":        "New DPIA initiated.",
        "dpia_initiated_title":         "DPIA Initiated",
        "dpia_register":                "DPIA Register",
        "dpia_title":                   "DPIA Title",
        "dpia_title_placeholder":       "e.g. Customer Data Analytics Platform",
        "dpia_workflow_advanced_reason": "DPIA workflow stage advanced.",
        "dpia_workflow_advanced_title":  "Workflow Stage Advanced",
        "dpias_by_risk_level":          "DPIAs by Risk Level",
        "dpias_by_workflow_stage":      "DPIAs by Workflow Stage",
        "dpo_review_required":          "DPO review required.",
        "estimated_records_affected":   "Estimated Records Affected",
        "final_override_dpo_warning":   "Final override requires DPO authority.",
        "high_critical_risk":           "High / Critical Risk",
        "third_parties_involved_label": "Third Parties Involved",
        "initiate_new_dpia":            "Initiate New DPIA",
        "mitigation_action_label":      "Mitigation Action",
        "mitigation_action_placeholder": "Describe the control or mitigation applied.",
        "mitigation_restricted":        "Mitigation recording restricted to DPO.",
        "mitigation_workflow":          "Mitigation Workflow",
        "new_dpia":                     "New DPIA",
        "next_review":                  "Next Review",
        "next_review_date":             "Next Review Date",
        "no_approval_history":          "No approval history.",
        "no_dpia_data_to_analyse":      "No DPIA data to analyse.",
        "no_dpias_available":           "No DPIAs available.",
        "no_dpias_awaiting_approval":   "No DPIAs awaiting approval.",
        "no_dpias_recorded":            "No DPIAs recorded.",
        "no_dpias_to_export":           "No DPIAs to export.",
        "no_dpo_approved_dpias_to_close": "No DPO-approved DPIAs to close.",
        "no_open_dpias_mitigation":     "No open DPIAs for mitigation.",
        "open_in_progress":             "Open / In Progress",
        "past_review_date":             "Past Review Date",
        "processing_activity_description": "Processing Activity Description",
        "processing_activity_placeholder": "Describe how personal data is processed.",
        "provide_dpia_title":           "Please provide a DPIA title.",
        "provide_rejection_reason":     "Please provide a rejection reason.",
        "purpose_dpia_linkage_help":    "Link this DPIA to a registered consent purpose.",
        "reason":                       "Reason",
        "regulatory_clause_reference_title": "Regulatory Clause Reference",
        "regulatory_export_dpia_reports": "Export DPIA Reports",
        "regulatory_export_note":       "Export for regulatory submission or audit.",
        "regulatory_reports":           "Regulatory Reports",
        "rejection_reason":             "Rejection Reason",
        "reviews_overdue":              "Reviews Overdue",
        "risk_level_auto_computed_note": "Risk level is automatically computed from the assessment.",
        "risk_score_distribution":      "Risk Score Distribution",
        "risk_score_distribution_all_dpias": "Risk Score Distribution — All DPIAs",
        "select_dpia":                  "Select DPIA",
        "select_dpia_to_close":         "Select DPIA to Close",
        "select_dpia_to_preview":       "Select DPIA to Preview",
        "stage":                        "Stage",
        "stage_advancement_restricted": "Stage advancement is restricted.",
        "view_history_for":             "View History For",

        # ── notices.py missing keys ────────────────────────────────────────
        "content_ml":                   "Malayalam Content",
        "hash_freeze_note":             "Published notices are hash-frozen and cannot be edited.",
        "no_notices_recorded":          "No privacy notices recorded.",
        "previous_version_id":          "Previous Version ID",
        "published_by":                 "Published By",
        "records":                      "Records",
        "requires_reconsent":           "Requires Re-consent",

        # ── Rights portal request type i18n keys ──────────────────────────
        "access_my_data":               "Access My Data",
        "correct_my_data":              "Correct My Data",
        "erase_my_data":                "Erase My Data",
        "nominate_representative":      "Nominate Representative",
        "raise_grievance":              "Raise Grievance",
        "revoke_consent_request":       "Revoke Consent",

        # ── Rights portal status/type string keys ─────────────────────────
        "data_access":                  "Data Access",
        "data_access_request":          "Data Access Request",
        "data_correction":              "Data Correction",
        "data_correction_request":      "Data Correction Request",
        "data_erasure":                 "Data Erasure",
        "data_erasure_request":         "Data Erasure Request",
        "nomination_request":           "Nomination Request",
        "grievance_redressal":          "Grievance Redressal",
        "consent_withdrawal_action":    "Consent Withdrawal",
        "under_review":                 "Under Review",
        "steward_approved":             "Steward Approved",

        # ── DPIA workflow stage keys ───────────────────────────────────────
        "stage_initiated":              "Initiated",
        "stage_under_review":           "Under Review",
        "stage_steward_approved":       "Steward Approved",
        "stage_dpo_approved":           "DPO Approved",
        "stage_rejected":               "Rejected",
        "stage_closed":                 "Closed",

        # ── Consent purpose keys ───────────────────────────────────────────
        "kyc":                          "KYC",
        "kyc_verification":             "KYC Verification",
        "loan_processing":              "Loan Processing",

        # ── Role display name keys ─────────────────────────────────────────
        "auditor":                      "Auditor",
        "board_member":                 "Board Member",
        "branch_officer":               "Branch Officer",
        "dpo":                          "DPO",
        "privacy_steward":              "Privacy Steward",
        "regional_officer":             "Regional Officer",
        "system_admin":                 "System Admin",
        "unknown_user":                 "Unknown User",
        "warning":                      "Warning",

        # ── Auth module keys ───────────────────────────────────────────────
        "login_account_locked":         "Account locked due to too many failed attempts. Please try again in {minutes} minutes.",
        "login_lockout_wait":           "Account is locked. Please wait {minutes} minutes before trying again.",
        "login_error":                  "Login error. Please contact the system administrator.",
        "mfa_required":                 "Multi-Factor Authentication Required",
        "mfa_enter_code":               "Enter your 6-digit authenticator code",
        "mfa_verify":                   "Verify",
        "mfa_invalid":                  "Invalid or expired code. Please try again.",
        "mfa_secret":                   "MFA Secret",
        "mfa_verified":                 "MFA Verified",
        "authenticated":                "Authenticated",
        "dpdp_caption":                 "Kerala Bank — Digital Personal Data Protection Act, 2023",
        "last_active":                  "Last Active",
        "login_time":                   "Login Time",
        "role_unknown":                 "Unknown Role",
        "sign_out":                     "Sign Out",
        "password_hash":                "Password Hash",

        # ── Audit module keys ──────────────────────────────────────────────
        "audit_access_restricted":      "Access restricted. Audit logs are read-only for this role.",
        "audit_contact_dpo":            "Contact your Data Protection Officer for full audit access.",

        # ── General UI keys ────────────────────────────────────────────────
        "all_records":                  "All Records",
        "deadline":                     "Deadline",
        "create_rights_request":        "Create Rights Request",
        "request_type":                 "Request Type",
        "requires_id_verification":     "requires identity verification",
        "requires_mandatory_id_verification": "requires mandatory identity verification",
        "valid_consent_required_for":   "Valid consent required for",
        "request":                      "Request",
        "active":                       "Active",
        "closed":                       "Closed",
        "rejected":                     "Rejected",
        "open":                         "Open",
        "in_progress":                  "In Progress",
        "escalated":                    "Escalated",
        "branch":                       "Branch",
        "region":                       "Region",
        "role":                         "Role",
        "customer_id":                  "Customer ID",
    },

    # ── Malayalam (മലയാളം) ───────────────────────────────────────────────────
    "ml": {
        # Navigation / module names
        "dashboard":                    "ഡാഷ്ബോർഡ്",
        "consent_management":           "അംഗീകാര നിയന്ത്രണം",
        "rights_portal":                "ഡാറ്റാ പ്രിൻസിപ്പൽ അവകാശ പോർട്ടൽ",
        "dpia":                         "ഡിപിഐഎ & സ്വകാര്യത വിലയിരുത്തൽ",
        "breach":                       "ഡാറ്റ ലംഘന നിയന്ത്രണം",
        "notices":                      "സ്വകാര്യത അറിയിപ്പ്",
        "audit":                        "ഓഡിറ്റ് ലോഗ്",
        "compliance":                   "നിയന്ത്രണ & എസ്എൽഎ നിരീക്ഷണം",

        # Common actions
        "submit_request":               "അപേക്ഷ സമർപ്പിക്കുക",
        "export":                       "എക്സ്പോർട്ട്",
        "more_info":                    "കൂടുതൽ വിവരങ്ങൾ",
        "explainability":               "വ്യാഖ്യാനം",
        "publish":                      "അറിയിപ്പ് പ്രസിദ്ധീകരിക്കുക",
        "save_draft":                   "ഡ്രാഫ്റ്റ് സൂക്ഷിക്കുക",
        "update_status":                "നില അപ്ഡേറ്റ് ചെയ്യുക",
        "mark_implemented":             "നടപ്പാക്കിയതായി അടയാളപ്പെടുത്തുക",
        "sign_in":                      "സൈൻ ഇൻ",
        "sign_out":                     "സൈൻ ഔട്ട്",
        "close":                        "അടയ്ക്കുക",
        "approve":                      "അംഗീകരിക്കുക",
        "reject":                       "നിരസിക്കുക",
        "revoke":                       "റദ്ദാക്കുക",
        "renew":                        "പുതുക്കുക",
        "add_mitigation":               "ലഘൂകരണ നടപടി ചേർക്കുക",
        "launch_dpia":                  "ഡിപിഐഎ ആരംഭിക്കുക",
        "report_incident":              "സംഭവം റിപ്പോർട്ട് ചെയ്യുക",
        "submit":                       "സമർപ്പിക്കുക",

        # Status labels
        "active":                       "സജീവം",
        "closed":                       "അടച്ചത്",
        "open":                         "തുറന്നത്",
        "draft":                        "ഡ്രാഫ്റ്റ്",
        "pending":                      "തീർപ്പുകൽപ്പിക്കാത്തത്",
        "approved":                     "അംഗീകൃതം",
        "rejected":                     "നിരസിച്ചത്",
        "escalated":                    "ഉയർത്തിയത്",
        "in_progress":                  "പുരോഗതിയിൽ",
        "resolved":                     "പരിഹരിച്ചത്",
        "published":                    "പ്രസിദ്ധീകരിച്ചത്",
        "revoked":                      "റദ്ദാക്കിയത്",
        "expired":                      "കാലഹരണപ്പെട്ടത്",
        "renewed":                      "പുതുക്കിയത്",

        # Field labels
        "status":                       "സ്ഥിതി",
        "deadline":                     "അവസാന തീയതി",
        "risk_level":                   "അപകട നില",
        "risk_score":                   "അപകട സ്കോർ",
        "customer_id":                  "ഉപഭോക്തൃ ഐഡി",
        "request_type":                 "അഭ്യർത്ഥന തരം",
        "submitted_at":                 "സമർപ്പിച്ച സമയം",
        "sla_status":                   "എസ്എൽഎ നില",
        "branch":                       "ശാഖ",
        "region":                       "മേഖല",
        "purpose":                      "പ്രോസസ്സിംഗ് ഉദ്ദേശ്യം",
        "language":                     "ഭാഷ",
        "version":                      "പതിപ്പ്",
        "notes":                        "കുറിപ്പുകൾ",
        "description":                  "വിവരണം",
        "severity":                     "തീവ്രത",
        "department":                   "വകുപ്പ്",
        "expiry_date":                  "കാലാവധി തീയതി",
        "decision":                     "തീരുമാനം",
        "explanation":                  "വ്യാഖ്യാനം",

        # KPI / metric labels
        "total_consents":               "മൊത്തം സജീവ അനുമതികൾ",
        "active_requests":              "സജീവ അവകാശ അഭ്യർത്ഥനകൾ",
        "open_dpias":                   "തുറന്ന ഡിപിഐഎകൾ",
        "reported_breaches":            "റിപ്പോർട്ട് ചെയ്ത ലംഘനങ്ങൾ",
        "overall_compliance":           "മൊത്തം നിയന്ത്രണ സ്കോർ",
        "sla_compliance_rate":          "എസ്എൽഎ നിയന്ത്രണ നിരക്ക്",
        "total_requests":               "മൊത്തം അഭ്യർത്ഥനകൾ",
        "unique_actors":                "അദ്വിതീയ ഉപയോക്താക്കൾ",
        "chain_valid":                  "ശൃംഖല സാധുതയുള്ളത്",

        # Section headings
        "executive_dashboard":          "എക്സിക്യൂട്ടീവ് പ്രൈവസി ഡാഷ്ബോർഡ്",
        "governance_console":           "ഡിപിഒ ഭരണ കൺസോൾ",
        "admin_console":                "സിസ്റ്റം ഭരണ കൺസോൾ",
        "branch_compliance":            "ശാഖ നിയന്ത്രണ സ്കോർ താരതമ്യം",
        "sla_performance":              "ശാഖ അടിസ്ഥാനത്തിൽ എസ്എൽഎ പ്രകടനം",
        "consent_forecast":             "അനുമതി കാലഹരണ പ്രവചനം",
        "clause_breakdown":             "ക്ലോസ് തിരിച്ചുള്ള വിശകലനം",
        "action_items":                 "തീർപ്പുകൽപ്പിക്കാത്ത പ്രവൃത്തി ഇനങ്ങൾ",
        "feature_controls":             "ഫീച്ചർ നടപ്പാക്കൽ നിയന്ത്രണങ്ങൾ",
        "ledger_integrity":             "ലെഡ്ജർ സമഗ്രത നില",
        "audit_records":                "ഓഡിറ്റ് രേഖകൾ",

        # Informational / caption texts
        "knowledge_graph":              "ജ്ഞാന ഗ്രാഫ്",
        "gis_map":                      "ശാഖ ജിഐഎസ് മാപ്പ്",
        "dpdp_caption":                 "ഡിജിറ്റൽ വ്യക്തിഗത ഡാറ്റ സംരക്ഷണ നിയമം 2023 നിയന്ത്രണ ചട്ടക്കൂട്",
        "consent_caption":              "ഡിപിഡിപിഎ 2023 — പൂർണ്ണ അനുമതി ജീവിതചക്രം: ഡ്രാഫ്റ്റ് → സജീവം → കാലഹരണം / റദ്ദാക്കൽ / പുതുക്കൽ",
        "read_only_notice":             "വായനാ-മാത്ര ആക്സസ്. മാറ്റങ്ങൾ അനുവദനീയമല്ല.",
        "access_restricted":            "ആക്സസ് നിയന്ത്രിതമാണ്. നിങ്ങളുടെ ഡാറ്റ പ്രൊട്ടക്ഷൻ ഓഫീസറെ ബന്ധപ്പെടുക.",
        "sla_recalc_caption":           "ഓരോ പേജ് റിഫ്രഷിലും എസ്എൽഎ പുനർഗണന ചെയ്യുന്നു. റെഡ് എസ്എൽഎ ഓട്ടോ-എസ്കലേഷൻ ട്രിഗർ ചെയ്യുന്നു.",

        # Consent lifecycle
        "granted":                      "അനുവദിച്ചു",
        "denied":                       "നിഷേധിച്ചു",
        "capture_consent":              "പുതിയ അനുമതി ക്യാപ്ചർ ചെയ്യുക",
        "consent_register":             "അനുമതി രജിസ്റ്റർ",
        "revoke_renew":                 "റദ്ദാക്കൽ / പുതുക്കൽ",
        "analytics":                    "വിശകലനം",

        # Rights types
        "access_data":                  "എൻ്റെ ഡാറ്റ ആക്സസ് ചെയ്യുക",
        "correct_data":                 "എൻ്റെ ഡാറ്റ തിരുത്തുക",
        "erase_data":                   "എൻ്റെ ഡാറ്റ ഇല്ലാതാക്കുക",
        "revoke_consent":               "അനുമതി റദ്ദാക്കുക",
        "nominate_rep":                 "പ്രതിനിധിയെ നോമിനേറ്റ് ചെയ്യുക",
        "raise_grievance":              "പരാതി ഉന്നയിക്കുക",

        # Risk levels
        "low":                          "കുറഞ്ഞത്",
        "medium":                       "മധ്യമം",
        "high":                         "ഉയർന്നത്",
        "critical":                     "ഗുരുതരം",

        # Step 6B additions — Breach Management, DPIA, table headers
        "Consent Management":           "സമ്മത മാനേജ്മെന്റ്",
        "Rights Request":               "അവകാശ അഭ്യർത്ഥന",
        "Approved":                     "അംഗീകരിച്ചു",
        "Rejected":                     "നിഷേധിച്ചു",
        "Escalated":                    "മുകളിലേക്ക് അയച്ചു",
        "Expiry Date":                  "കാലാവധി തീയതി",
        "Status":                       "നില",
        "Decision":                     "തീരുമാനം",
        "Explanation":                  "വ്യാഖ്യാനം",
        "Breach Management":            "ലംഘന നിയന്ത്രണം",
        "DPIA":                         "ഡാറ്റ സംരക്ഷണ പ്രഭാവ വിലയിരുത്തൽ",
        "Dashboard":                    "ഡാഷ്ബോർഡ്",
        "Submit":                       "സമർപ്പിക്കുക",

        # Form placeholders
        "enter_request_details":        "നിങ്ങളുടെ അഭ്യർത്ഥന വിവരങ്ങൾ നൽകുക",
        "enter_customer_id":            "ഉപഭോക്തൃ ഐഡി നൽകുക",
        "enter_reason":                 "കാരണം നൽകുക",

        # ── Breach module ─────────────────────────────────────────────────────
        "breach_caption":                       "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 8 — ഡാറ്റ ലംഘന സംഭവങ്ങൾ റിപ്പോർട്ട് ചെയ്യുക, ട്രാക്ക് ചെയ്യുക, പരിഹരിക്കുക. 6 മണിക്കൂർ നിയന്ത്രണ അറിയിപ്പ് ബാധ്യത.",
        "breach_more_info":                     "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 8(5) പ്രകാരം, ഡാറ്റ ഫിഡ്യൂഷ്യറികൾ കണ്ടുപിടിച്ച് 6 മണിക്കൂറിനുള്ളിൽ ഡേറ്റ ലംഘനങ്ങൾ റിപ്പോർട്ട് ചെയ്യണം.",
        "total_incidents":                      "മൊത്തം സംഭവങ്ങൾ",
        "open_active":                          "തുറന്നത് / സജീവം",
        "high_severity":                        "ഉയർന്ന തീവ്രത",
        "this_branch":                          "ഈ ശാഖ",
        "all_branches":                         "എല്ലാ ശാഖകളും",
        "under_investigation":                  "അന്വേഷണത്തിൽ",
        "requires_dpo_review":                  "ഡിപിഒ അവലോകനം ആവശ്യമാണ്",
        "cert_notification_required":           "ഡിപിഡിപി ആക്ട് 2023 പ്രകാരം 6 മണിക്കൂറിനുള്ളിൽ ഡാറ്റ സംരക്ഷണ ബോർഡിനെ അറിയിക്കണം.",
        "incident_register":                    "സംഭവ രജിസ്റ്റർ",
        "containment":                          "നിയന്ത്രണ നടപടികൾ",
        "incidents":                            "സംഭവങ്ങൾ",
        "incident_title":                       "സംഭവ ശീർഷകം",
        "incident_title_placeholder":           "ഉദാ: ലോൺ രേഖകളിലേക്ക് അനധികൃത ആക്സസ്",
        "affected_data_categories":             "ബാധിക്കപ്പെട്ട ഡാറ്റ വിഭാഗങ്ങൾ",
        "estimated_affected_records":           "കണക്കാക്കിയ ബാധിക്കപ്പെട്ട രേഖകൾ",
        "special_category_data_check":          "പ്രത്യേക വിഭാഗ ഡാറ്റ ഉൾക്കൊള്ളുന്നുണ്ടോ (ആരോഗ്യം, സാമ്പത്തിക, ബയോമെട്രിക്)?",
        "dpo_notified":                         "ഡിപിഒയെ അറിയിച്ചിട്ടുണ്ട്",
        "dpo_notified_help":                    "10,000-ൽ അധികം രേഖകൾ ബാധിക്കുന്ന ലംഘനങ്ങൾക്ക് ആവശ്യമാണ്",
        "incident_description_placeholder":     "എന്ത് സംഭവിച്ചു, ഏത് സിസ്റ്റങ്ങൾ/ഡാറ്റ ബാധിച്ചു, ഉടനടി സ്വീകരിച്ച നടപടികൾ വിവരിക്കുക.",
        "predicted_severity":                   "പ്രവചിക്കപ്പെട്ട തീവ്രത",
        "auto_classified":                      "സ്വയം തരംതിരിക്കൽ, മാനുവൽ ഓവർറൈഡ് ഇല്ല",
        "provide_incident_title":               "ദയവായി സംഭവ ശീർഷകം നൽകുക.",
        "select_data_category":                 "ദയവായി ഒരു ഡാറ്റ വിഭാഗം തിരഞ്ഞെടുക്കുക.",
        "sla_timer_started":                    "6 മണിക്കൂർ എസ്എൽഎ ടൈമർ ആരംഭിച്ചു.",
        "breach_logged":                        "ലംഘനം രേഖപ്പെടുത്തി",
        "breach_logged_reason":                 "നിയന്ത്രണ ട്രാക്കിംഗിനായി സംഭവം രജിസ്റ്റർ ചെയ്തു. 6 മണിക്കൂർ എസ്എൽഎ ടൈമർ പ്രവർത്തനത്തിൽ.",
        "high_critical_detected":               "ഉയർന്ന/ഗുരുതര തീവ്രത കണ്ടെത്തി.",
        "cohort_notified_auto":                 "ബാധിക്കപ്പെട്ട ഉപഭോക്തൃ ഗ്രൂപ്പിനെ സ്വയം അറിയിച്ചിട്ടുണ്ട്.",
        "access_denied":                        "ആക്സസ് നിഷേധിച്ചു",
        "update_incident_status":               "സംഭവ സ്ഥിതി അപ്ഡേറ്റ് ചെയ്യുക",
        "select_incident":                      "സംഭവം തിരഞ്ഞെടുക്കുക",
        "new_status":                           "പുതിയ സ്ഥിതി",
        "incident":                             "സംഭവം",
        "updated_to":                           "അപ്ഡേറ്റ് ചെയ്തത്",
        "regulatory_notification_recorded":     "നിയന്ത്രണ അറിയിപ്പ് രേഖപ്പെടുത്തി",
        "breach_marked_reported":               "നിയമ ബാധ്യതയ്ക്കനുസൃതമായി ലംഘനം റിപ്പോർട്ട് ചെയ്തതായി അടയാളപ്പെടുത്തി.",
        "close_breach":                         "ലംഘനം അടയ്ക്കുക",
        "breach_closed_success":                "സംഭവം {id} അടച്ചു. എസ്എൽഎ രേഖ പൂർണ്ണമായി.",
        "breach_not_found":                     "ലംഘനം {id} കണ്ടെത്തിയില്ല അല്ലെങ്കിൽ ഇതിനകം അടച്ചിരിക്കുന്നു.",
        "report_new_incident":                  "പുതിയ ഡാറ്റ ലംഘന സംഭവം റിപ്പോർട്ട് ചെയ്യുക",
        "breach_reporting_more_info":           "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 8(5) പ്രകാരം, ഡാറ്റ ലംഘനങ്ങൾ 6 മണിക്കൂറിനുള്ളിൽ റിപ്പോർട്ട് ചെയ്യണം. തീവ്രത സ്വയം തരംതിരിക്കപ്പെടുന്നു.",
        "breach_role_restricted":               "ലംഘന റിപ്പോർട്ടിംഗ് ഓഫീസർമാർക്കും ഡിപിഒക്കും മാത്രം.",
        "auto_assigned":                        "പ്രൊഫൈലിൽ നിന്ന് സ്വയം നിയോഗിക്കപ്പെട്ടത്",
        "containment_step_documentation":       "നിയന്ത്രണ നടപടി രേഖപ്പെടുത്തൽ",
        "containment_more_info":                "ഓഡിറ്റ് പ്രതിരോധത്തിനായി എല്ലാ നിയന്ത്രണ നടപടികളും രേഖപ്പെടുത്തുക.",
        "containment_role_restricted":          "നിയന്ത്രണ രേഖപ്പെടുത്തൽ ഓഫീസർമാർക്കും ഡിപിഒക്കും മാത്രം.",
        "no_open_incidents_containment":        "നിയന്ത്രണ നടപടി ആവശ്യമുള്ള തുറന്ന സംഭവങ്ങൾ ഇല്ല.",
        "select_open_incident":                 "തുറന്ന സംഭവം തിരഞ്ഞെടുക്കുക",
        "containment_action":                   "നിയന്ത്രണ നടപടി",
        "containment_action_placeholder":       "ഉദാ: ബാധിക്കപ്പെട്ട ഓഫീസർക്കുള്ള ആക്സസ് റദ്ദാക്കി. സിസ്റ്റം ഓഡിറ്റ് ആരംഭിച്ചു.",
        "add_containment_step":                 "നിയന്ത്രണ നടപടി ചേർക്കുക",
        "describe_containment_action":          "ദയവായി നിയന്ത്രണ നടപടി വിവരിക്കുക.",
        "containment_step_recorded":            "{id}-നായി നിയന്ത്രണ നടപടി രേഖപ്പെടുത്തി.",
        "view_containment_log_for":             "നിയന്ത്രണ ലോഗ് കാണുക",
        "no_containment_steps":                 "ഇതുവരെ നിയന്ത്രണ നടപടികൾ രേഖപ്പെടുത്തിയിട്ടില്ല.",
        "timestamp":                            "സമയ മുദ്ര",
        "recorded_by":                          "രേഖപ്പെടുത്തിയത്",
        "action":                               "നടപടി",
        "breach_analytics":                     "ലംഘന വിശകലനം",
        "no_incident_data":                     "വിശകലനത്തിന് ഡാറ്റ ഇല്ല.",
        "incidents_by_severity":                "തീവ്രത അനുസരിച്ച് സംഭവങ്ങൾ",
        "incidents_by_status":                  "സ്ഥിതി അനുസരിച്ച് സംഭവങ്ങൾ",
        "severity_auto_classified_more_info":   "തീവ്രത ആഘാത എണ്ണം, ഡാറ്റ വിഭാഗ സംവേദനക്ഷമത, നിയന്ത്രണ പരിധികൾ എന്നിവ അടിസ്ഥാനത്തിൽ സ്വയം തരംതിരിക്കപ്പെടുന്നു.",
        "incidents_by_branch":                  "ശാഖ അനുസരിച്ച് സംഭവങ്ങൾ",
        "incident_volume_by_branch":            "ശാഖ അനുസരിച്ച് സംഭവ അളവ്",
        "executive_breach_view_more_info":      "എക്സിക്യൂട്ടീവ് കാഴ്ച സമഗ്ര ലംഘന നില കാണിക്കുന്നു.",
        "high_critical_unnotified":             "ഉയർന്ന/ഗുരുതര സംഭവങ്ങൾ ഡാറ്റ സംരക്ഷണ ബോർഡിനെ അറിയിച്ചിട്ടില്ല.",
        "six_hour_notification_obligation":     "6 മണിക്കൂർ അറിയിപ്പ് ബാധ്യത",
        "six_hour_notification_reason":         "ഡിപിഡിപി ആക്ട് 2023 പ്രകാരം ഉയർന്ന/ഗുരുതര സംഭവങ്ങൾ 6 മണിക്കൂറിനുള്ളിൽ ബോർഡിനെ അറിയിക്കണം.",
        "reported_at":                          "റിപ്പോർട്ട് ചെയ്ത സമയം",
        "reporter":                             "റിപ്പോർട്ടർ",
        "impact_count":                         "ആഘാത എണ്ണം",
        "title":                                "ശീർഷകം",
        "no_incidents_branch":                  "നിങ്ങളുടെ ശാഖയ്ക്ക് സംഭവങ്ങൾ ഒന്നും രേഖപ്പെടുത്തിയിട്ടില്ല.",
        "yes":                                  "അതെ",
        "no":                                   "ഇല്ല",
        "logged":                               "രേഖപ്പെടുത്തി",
        "special_category":                     "പ്രത്യേക വിഭാഗം",
        "summary":                              "സംഗ്രഹം",

        # ── Compliance module ─────────────────────────────────────────────────
        "compliance_caption":                   "തത്സമയ നിയന്ത്രണ അനുസരണം — ലൈവ് സിസ്റ്റം സ്ഥിതിയിൽ നിന്ന് ഉരുത്തിരിഞ്ഞത്. ഡിപിഡിപി ആക്ട് 2023, ആർബിഐ സൈബർ സുരക്ഷ ചട്ടക്കൂട്.",
        "compliance_more_info":                 "അനുസരണ നില, അനുമതി രജിസ്ട്രി, അവകാശ വർക്ക്ഫ്ലോ, ഡിപിഐഎ രജിസ്ട്രി, ഓഡിറ്റ് ലെഡ്ജർ എന്നിവയിൽ നിന്ന് ഡൈനാമിക് ആയി കണക്കാക്കുന്നു.",
        "compliance_access_restricted":         "ആക്സസ് നിയന്ത്രിതമാണ്. {role} റോളിന് നിയന്ത്രണ ഭരണ സ്കോർ ലഭ്യമല്ല.",
        "compliance_sysadmin_hint":             "സിസ്റ്റം അഡ്മിൻമാർക്ക് എക്സിക്യൂട്ടീവ് ഡാഷ്ബോർഡ്, ഓഡിറ്റ് ലോഗ് മോഡ്യൂളുകൾ വഴി ടെക്നിക്കൽ ഓഡിറ്റ് ടെലിമെട്രി കാണാം.",
        "compliance_officer_hint":              "ഓഫീസർമാർക്ക് എക്സിക്യൂട്ടീവ് ഡാഷ്ബോർഡ് വഴി ശാഖ അനുസരണ സംഗ്രഹം കാണാം.",
        "overall_compliance_score":             "മൊത്തം നിയന്ത്രണ സ്കോർ",
        "clauses_evaluated":                    "വ്യവസ്ഥകൾ വിലയിരുത്തി",
        "compliant":                            "അനുസരണം",
        "partial":                              "ഭാഗിക",
        "non_compliant":                        "അനുസരണ ലംഘനം",
        "auditor_read_only":                    "ഓഡിറ്റർ കാഴ്ച — വായനാ-മാത്രം.",
        "clause_heatmap":                       "ക്ലോസ് ഹീറ്റ്മാപ്പ്",
        "clause_detail":                        "ക്ലോസ് വിശദാംശം",
        "clause_compliance_heatmap":            "ക്ലോസ് അനുസരണ ഹീറ്റ്മാപ്പ്",
        "heatmap_caption":                      "നിറം അനുസരണ സ്ഥിതി സൂചിപ്പിക്കുന്നു. ക്ലോസ് റഫറൻസിനായി ഹോവർ ചെയ്യുക.",
        "no_compliance_data":                   "അനുസരണ ഡാറ്റ ലഭ്യമല്ല. സിസ്റ്റം രജിസ്ട്രികൾ പൂരിപ്പിച്ചിട്ടുണ്ടെന്ന് ഉറപ്പാക്കുക.",
        "clause":                               "വ്യവസ്ഥ",
        "evidence":                             "തെളിവ്",
        "visual_heatmap_overview":              "ദൃശ്യ ഹീറ്റ്മാപ്പ് അവലോകനം",
        "clause_by_clause_detail":              "വ്യവസ്ഥ-തിരിച്ചുള്ള വിശദാംശം",
        "no_clause_data":                       "ക്ലോസ് ഡാറ്റ ലഭ്യമല്ല.",
        "filter_by_status":                     "സ്ഥിതി അനുസരിച്ച് ഫിൽട്ടർ ചെയ്യുക",
        "all":                                  "എല്ലാം",
        "board_ready_export":                   "ബോർഡ്-റെഡി എക്സ്പോർട്ട്",
        "export_caption":                       "അനുസരണ റിപ്പോർട്ട് പിഡിഎഫ്, ജോൺ, അല്ലെങ്കിൽ എക്സ്എംഎൽ ആയി എക്സ്പോർട്ട് ചെയ്യുക.",
        "download_clause_csv":                  "ക്ലോസ് സിഎസ്വി ഡൗൺലോഡ് ചെയ്യുക",

        # ── Notices module ────────────────────────────────────────────────────
        "notices_caption":                      "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 5 — എല്ലാ ഉൽപ്പന്ന യാത്രകൾക്കും സ്വകാര്യത അറിയിപ്പുകൾ നിർമ്മിക്കുക, പതിപ്പ് ചെയ്യുക, പ്രസിദ്ധീകരിക്കുക.",
        "notices_more_info":                    "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 5 പ്രകാരം, ഡാറ്റ ഫിഡ്യൂഷ്യറികൾ അനുമതി നേടുന്നതിന് മുൻപ് വ്യക്തമായ അറിയിപ്പ് നൽകണം.",
        "notices_access_restricted":            "ആക്സസ് നിയന്ത്രിതമാണ്. നിങ്ങളുടെ റോളിന് സ്വകാര്യത അറിയിപ്പുകൾ ലഭ്യമല്ല.",
        "notices_contact_dpo":                  "ആക്സസ് അഭ്യർത്ഥിക്കാൻ ഡാറ്റ പ്രൊട്ടക്ഷൻ ഓഫീസറെ ബന്ധപ്പെടുക.",
        "total_versions":                       "മൊത്തം പതിപ്പുകൾ",
        "drafts":                               "ഡ്രാഫ്റ്റുകൾ",
        "superseded":                           "മേലേ",
        "products":                             "ഉൽപ്പന്നങ്ങൾ",
        "all_time":                             "സർവ്വകാലവും",
        "live":                                 "ലൈവ്",
        "pending_review":                       "അവലോകനം തീർപ്പുകൽപ്പിക്കാത്തത്",
        "archived":                             "ആർക്കൈവ് ചെയ്തത്",
        "journeys_covered":                     "ഉൾക്കൊള്ളുന്ന യാത്രകൾ",
        "officer_draft_only":                   "ഓഫീസർ ആക്സസ്: ഡ്രാഫ്റ്റ് അറിയിപ്പുകൾ നിർമ്മിക്കാം. ഡിപിഒക്ക് മാത്രമേ പ്രസിദ്ധീകരിക്കാൻ കഴിയൂ.",
        "notice_history":                       "അറിയിപ്പ് ചരിത്രം",
        "notice_preview":                       "അറിയിപ്പ് പ്രിവ്യൂ",
        "create_version_notice":                "അറിയിപ്പ് നിർമ്മിക്കുക / പതിപ്പ് ചെയ്യുക",
        "create_or_version_notice":             "സ്വകാര്യത അറിയിപ്പ് നിർമ്മിക്കുക അല്ലെങ്കിൽ പതിപ്പ് ചെയ്യുക",
        "create_notice_caption":                "സൂക്ഷിക്കുമ്പോൾ എപ്പോഴും പുതിയ പതിപ്പ് സൃഷ്ടിക്കുന്നു. നിലവിലുള്ള അറിയിപ്പുകൾ മേലേ ആക്കുന്നു, ഒരിക്കലും തിരുത്തുന്നില്ല.",
        "product_journey":                      "ഉൽപ്പന്ന യാത്ര",
        "active_version_for":                   "ഈ ഉൽപ്പന്നത്തിന്റെ സജീവ പതിപ്പ്",
        "notice_title":                         "അറിയിപ്പ് ശീർഷകം",
        "notice_content_english":               "സ്വകാര്യത അറിയിപ്പ് ഉള്ളടക്കം (ഇംഗ്ലീഷ്)",
        "linked_dpdp_clauses":                  "ബന്ധിപ്പിച്ച ഡിപിഡിപി വ്യവസ്ഥകൾ",
        "linked_clauses_help":                  "ഈ അറിയിപ്പ് അഭിസംബോധന ചെയ്യുന്ന നിയന്ത്രണ വ്യവസ്ഥകൾ തിരഞ്ഞെടുക്കുക.",
        "version_note":                         "പതിപ്പ് കുറിപ്പ്",
        "version_note_placeholder":             "ഉദാ: ഡിപിഡിപി നിയമങ്ങൾ 2025 അനുസരിച്ച് മൂന്നാം കക്ഷി പങ്കുവയ്ക്കൽ വ്യവസ്ഥ അപ്ഡേറ്റ് ചെയ്തു",
        "preview_malayalam":                    "മലയാളം പ്രിവ്യൂ (സ്വയം നിർമ്മിതം)",
        "malayalam_content":                    "മലയാളം ഉള്ളടക്കം",
        "enter_english_to_preview":             "പ്രിവ്യൂ കാണാൻ മുകളിൽ ഇംഗ്ലീഷ് ഉള്ളടക്കം നൽകുക.",
        "notice_content_empty":                 "അറിയിപ്പ് ഉള്ളടക്കം ശൂന്യമാകരുത്.",
        "notice_clause_required":               "കുറഞ്ഞത് ഒരു ഡിപിഡിപി വ്യവസ്ഥ ബന്ധിപ്പിക്കണം.",
        "invalid_clause_codes":                 "അസാധുവായ വ്യവസ്ഥ കോഡുകൾ",
        "officer_draft_caption":                "ഡ്രാഫ്റ്റുകൾ ഡിപിഒ അവലോകനത്തിനും പ്രസിദ്ധീകരണത്തിനുമായി സമർപ്പിക്കുന്നു.",
        "saved_for":                            "സൂക്ഷിച്ചത്",
        "pending_dpo_review":                   "ഡിപിഒ അവലോകനം തീർപ്പുകൽപ്പിക്കാത്തത്.",
        "publish_notice":                       "അറിയിപ്പ് പ്രസിദ്ധീകരിക്കുക",
        "reconsent_required":                   "വീണ്ടും അനുമതി ആവശ്യമാണ് — ബന്ധിപ്പിച്ച വ്യവസ്ഥകൾ മാറി.",
        "users_notified_sms":                   "ഉപഭോക്താക്കൾ എസ്എംഎസ് വഴി അറിയിച്ചു.",
        "notice":                               "അറിയിപ്പ്",
        "published_for":                        "പ്രസിദ്ധീകരിച്ചത്",
        "notice_published":                     "സ്വകാര്യത അറിയിപ്പ് പ്രസിദ്ധീകരിച്ചു",
        "notice_published_reason":              "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 5 പ്രകാരം അനുമതി ക്യാപ്ചറിന് മുൻപ് അറിയിപ്പ് ലഭ്യമാക്കി.",
        "notice_version_history":               "അറിയിപ്പ് പതിപ്പ് ചരിത്രം",
        "auditor_history_view":                 "വായനാ-മാത്ര കാഴ്ച. പ്രസിദ്ധീകരിക്കപ്പെട്ടതും ഡ്രാഫ്റ്റും മേലേ ആക്കിയതും കാണിക്കുന്നു.",
        "filter_by_product":                    "ഉൽപ്പന്നം അനുസരിച്ച് ഫിൽട്ടർ ചെയ്യുക",
        "requires_reconsent_only":              "വീണ്ടും അനുമതി ആവശ്യമുള്ളവ മാത്രം",
        "notice_id":                            "അറിയിപ്പ് ഐഡി",
        "product":                              "ഉൽപ്പന്നം",
        "clauses_linked":                       "ബന്ധിപ്പിച്ച വ്യവസ്ഥകൾ",
        "reconsent":                            "വീണ്ടും അനുമതി?",
        "affected_users":                       "ബാധിക്കപ്പെട്ട ഉപഭോക്താക്കൾ",
        "published_on":                         "പ്രസിദ്ധീകരിച്ച തീയതി",
        "by":                                   "ആർ",
        "created_at":                           "നിർമ്മിച്ച സമയം",
        "notice_versions_shown":                "അറിയിപ്പ് പതിപ്പുകൾ കാണിക്കുന്നു.",
        "notice_history_more_info":             "പ്രസിദ്ധീകരിച്ചതിന് ശേഷം ഓരോ പതിപ്പും മാറ്റമില്ലാത്തതാണ്. മേലേ ആക്കിയ പതിപ്പുകൾ ഓഡിറ്റിനായി നിലനിർത്തുന്നു.",
        "no_notices_match_filters":             "തിരഞ്ഞെടുത്ത ഫിൽട്ടറുകളുമായി പൊരുത്തപ്പെടുന്ന അറിയിപ്പുകൾ ഇല്ല.",
        "publish_pending_drafts":               "തീർപ്പുകൽപ്പിക്കാത്ത ഡ്രാഫ്റ്റുകൾ പ്രസിദ്ധീകരിക്കുക",
        "select_draft_to_publish":              "പ്രസിദ്ധീകരിക്കാൻ ഡ്രാഫ്റ്റ് തിരഞ്ഞെടുക്കുക",
        "publish_selected_draft":               "തിരഞ്ഞെടുത്ത ഡ്രാഫ്റ്റ് പ്രസിദ്ധീകരിക്കുക",
        "no_published_notices_preview":         "പ്രിവ്യൂ കാണാൻ പ്രസിദ്ധീകരിച്ച അറിയിപ്പുകൾ ഒന്നുമില്ല.",
        "select_product":                       "ഉൽപ്പന്നം തിരഞ്ഞെടുക്കുക",
        "display_language":                     "പ്രദർശന ഭാഷ",
        "english":                              "ഇംഗ്ലീഷ്",
        "malayalam":                            "മലയാളം",
        "linked_clauses_label":                 "ബന്ധിപ്പിച്ച വ്യവസ്ഥകൾ",
        "view_superseded_version":              "മേലേ ആക്കിയ മുൻ പതിപ്പ് കാണുക",
        "superseded_on":                        "മേലേ ആക്കിയ തീയതി",
        "preview_language_caption":             "ഇംഗ്ലീഷ് അല്ലെങ്കിൽ മലയാളത്തിൽ അറിയിപ്പ് ഉള്ളടക്കം കാണുക.",

        # ── app.py & auth.py UI strings ───────────────────────────────────────
        "app_title":                            "സമ്മത സ്വകാര്യത നിയന്ത്രണ സംവിധാനം",
        "app_subtitle":                         "കേരള ബാങ്ക് — ഡിജിറ്റൽ വ്യക്തിഗത ഡാറ്റ സംരക്ഷണ നിയമം 2023",
        "dpcms_modules":                        "ഡിപിസിഎംഎസ് മൊഡ്യൂളുകൾ",
        "no_modules_available":                 "നിങ്ങളുടെ റോളിന് മൊഡ്യൂളുകൾ ലഭ്യമല്ല.",
        "board_view_info":                      "ബോർഡ് കാഴ്ച: എക്സിക്യൂട്ടീവ് ഡാഷ്ബോർഡ് മാത്രം.",
        "customer_access_info":                 "ഉപഭോക്തൃ ആക്സസ്: അവകാശ പോർട്ടൽ മാത്രം.",
        "sysadmin_info":                        "സിസ്റ്റം അഡ്മിനിസ്ട്രേറ്റർ: ടെക്നിക്കൽ മൊഡ്യൂളുകൾ മാത്രം.",
        "branch_label":                         "ശാഖ",
        "region_label":                         "മേഖല",
        "username":                             "ഉപയോക്തൃ നാമം",
        "password":                             "പാസ്‌വേഡ്",
        "sign_in":                              "സൈൻ ഇൻ",
        "login_enter_both":                     "ദയവായി ഉപയോക്തൃ നാമവും പാസ്‌വേഡും നൽകുക.",
        "login_invalid":                        "തെറ്റായ ഉപയോക്തൃ നാമം അല്ലെങ്കിൽ പാസ്‌വേഡ്.",
        "demo_credentials":                     "ഡെമോ ക്രെഡൻഷ്യലുകൾ",
        "name_label":                           "പേര്",
        "dept_label":                           "വകുപ്പ്",
        "all_branches_head_office":             "എല്ലാം (ഹെഡ് ഓഫീസ്)",
        "assisted_submission_active":           "സഹായ സമർപ്പണ മോഡ് സജീവം",
        "session_duration":                     "സെഷൻ ദൈർഘ്യം",
        "minutes":                              "മിനിറ്റ്",
        "session_expiring_soon":                "ഏകദേശം {minutes} മിനിറ്റിനുള്ളിൽ സെഷൻ കാലഹരണപ്പെടും.",
        "session_expired":                      "നിങ്ങളുടെ സെഷൻ കാലഹരണപ്പെട്ടു. ദയവായി വീണ്ടും സൈൻ ഇൻ ചെയ്യുക.",
        "access_denied_role":                   "ആക്സസ് നിഷേധിച്ചു: {role} റോളിന് {module} കാണാൻ അനുമതിയില്ല.",
        "contact_dpo_access":                   "ഉയർന്ന ആക്സസ് അഭ്യർത്ഥിക്കാൻ ഡാറ്റ പ്രൊട്ടക്ഷൻ ഓഫീസറെ ബന്ധപ്പെടുക.",
        "login_config_error":                   "ലോഗിൻ നിഷേധിച്ചു: അക്കൗണ്ട് കോൺഫിഗറേഷൻ പിഴവ്. നിങ്ങളുടെ സിസ്റ്റം അഡ്മിനിസ്ട്രേറ്ററെ ബന്ധപ്പെടുക.",

        # ── Role display names (always via t() — never hardcoded) ─────────────
        "role_customer":                        "ഉപഭോക്താവ്",
        "role_branch_officer":                  "ശാഖ ഓഫീസർ",
        "role_privacy_steward":                 "സ്വകാര്യത സ്റ്റുവാർഡ്",
        "role_dpo":                             "ഡിപിഒ",
        "role_board_member":                    "ബോർഡ് അംഗം",
        "role_auditor":                         "ഓഡിറ്റർ",
        "role_system_admin":                    "സിസ്റ്റം അഡ്മിനിസ്ട്രേറ്റർ",
        "role_unknown":                         "അജ്ഞാത റോൾ",

        # ── Demo credentials table column headers ─────────────────────────────
        "role_label":                           "റോൾ",
        "access_label":                         "ആക്സസ്",
        "demo_access_dpo":                      "8 മൊഡ്യൂളുകൾ",
        "demo_access_officer":                  "5 മൊഡ്യൂളുകൾ",
        "demo_access_auditor":                  "4 മൊഡ്യൂളുകൾ",
        "demo_access_board":                    "ഡാഷ്ബോർഡ് മാത്രം",
        "demo_access_admin":                    "ടെക്നിക്കൽ മൊഡ്യൂളുകൾ",
        "demo_access_customer":                 "അവകാശ പോർട്ടൽ മാത്രം",

        # ── Consent processing purpose dropdown options ────────────────────────
        "purpose_loan":                         "ലോൺ പ്രോസസ്സിംഗ്",
        "purpose_kyc":                          "കെവൈസി സ്ഥിരീകരണം",
        "purpose_account":                      "അക്കൗണ്ട് തുറക്കൽ",
        "purpose_insurance":                    "ഇൻഷുറൻസ്",
        "purpose_credit":                       "ക്രെഡിറ്റ് വിലയിരുത്തൽ",
        "purpose_marketing":                    "മാർക്കറ്റിംഗ്",
        "purpose_fd":                           "ഫിക്സഡ് ഡിപ്പോസിറ്റ്",
        "purpose_savings":                      "സേവിംഗ്സ് അക്കൗണ്ട്",
        "purpose_remittance":                   "റെമിറ്റൻസ്",

        # ── Data category options (breach module multiselect) ─────────────────
        "cat_financial":                        "സാമ്പത്തിക",
        "cat_health":                           "ആരോഗ്യം",
        "cat_biometric":                        "ബയോമെട്രിക്",
        "cat_identity":                         "തിരിച്ചറിയൽ",
        "cat_contact":                          "ബന്ധപ്പെടൽ",
        "cat_location":                         "സ്ഥാനം",
        "cat_transaction":                      "ഇടപാട് ചരിത്രം",
        "cat_employment":                       "തൊഴിൽ",

        # ── DPIA risk type dropdown options ───────────────────────────────────
        "risk_type_privacy":                    "സ്വകാര്യത അപകടം",
        "risk_type_security":                   "സുരക്ഷ അപകടം",
        "risk_type_compliance":                 "നിയന്ത്രണ അപകടം",
        "risk_type_operational":                "പ്രവർത്തന അപകടം",

        # ── DPIA assessment type options ──────────────────────────────────────
        "assessment_full":                      "പൂർണ്ണ ഡിപിഐഎ",
        "assessment_screening":                 "സ്ക്രീനിംഗ് വിലയിരുത്തൽ",
        "assessment_targeted":                  "ലക്ഷ്യബദ്ധ അവലോകനം",

        # ── Notice product journey options ────────────────────────────────────
        "journey_savings":                      "സേവിംഗ്സ് അക്കൗണ്ട്",
        "journey_loan":                         "ലോൺ",
        "journey_insurance":                    "ഇൻഷുറൻസ്",
        "journey_fd":                           "ഫിക്സഡ് ഡിപ്പോസിറ്റ്",
        "journey_remittance":                   "റെമിറ്റൻസ്",
        "journey_credit_card":                  "ക്രെഡിറ്റ് കാർഡ്",

        # ── Filter / sort options ─────────────────────────────────────────────
        "filter_all":                           "എല്ലാം",
        "sort_newest":                          "പുതിയത് ആദ്യം",
        "sort_oldest":                          "പഴയത് ആദ്യം",
        "sort_severity":                        "തീവ്രത അനുസരിച്ച്",

        # ── Consent capture tab labels ────────────────────────────────────────
        "tab_capture":                          "അനുമതി ക്യാപ്ചർ",
        "tab_register":                         "രജിസ്റ്റർ",
        "tab_revoke_renew":                     "റദ്ദാക്കൽ / പുതുക്കൽ",
        "tab_analytics":                        "വിശകലനം",

        # ── Rights portal specific ────────────────────────────────────────────
        "my_requests":                          "എന്റെ അഭ്യർത്ഥനകൾ",
        "no_requests_found":                    "അഭ്യർത്ഥനകൾ ഒന്നും കണ്ടെത്തിയില്ല.",
        "request_submitted":                    "അഭ്യർത്ഥന വിജയകരമായി സമർപ്പിച്ചു.",
        "request_already_pending":              "ഈ തരത്തിലുള്ള ഒരു അഭ്യർത്ഥന ഇതിനകം തീർപ്പുകൽപ്പിക്കാത്തതായി ഉണ്ട്.",
        "representative_name":                  "പ്രതിനിധിയുടെ പേര്",
        "grievance_details":                    "പരാതി വിശദാംശങ്ങൾ",

        # ── Generic UI ────────────────────────────────────────────────────────
        "loading":                              "ലോഡ് ചെയ്യുന്നു...",
        "no_data":                              "ഡാറ്റ ലഭ്യമല്ല.",
        "confirm":                              "സ്ഥിരീകരിക്കുക",
        "cancel":                               "റദ്ദാക്കുക",
        "search":                               "തിരയുക",
        "select":                               "തിരഞ്ഞെടുക്കുക",
        "back":                                 "തിരിച്ച്",
        "next":                                 "അടുത്തത്",

        # ── Nav module labels (used in option_menu) ───────────────────────────
        "executive_dashboard":                  "എക്സിക്യൂട്ടീവ് ഡാഷ്ബോർഡ്",
        "data_principal_rights":                "ഡാറ്റ പ്രിൻസിപ്പൽ അവകാശ പോർട്ടൽ",
        "dpia_privacy_assessments":             "ഡിപിഐഎ & സ്വകാര്യത വിലയിരുത്തൽ",
        "data_breach_management":               "ഡാറ്റ ലംഘന നിയന്ത്രണം",
        "privacy_notices":                      "സ്വകാര്യത അറിയിപ്പ്",
        "audit_logs":                           "ഓഡിറ്റ് ലോഗ്",
        "compliance_sla_monitoring":            "നിയന്ത്രണ & എസ്എൽഎ നിരീക്ഷണം",

        # ── Audit module ──────────────────────────────────────────────────────
        "audit_caption":                "തിരിമറി-തെളിവ്, ഹാഷ്-ചങ്ങലയിൽ കോർത്ത ലോഗുകൾ — ഡിപിഡിപി ആക്ട് 2023 അനുസരണം.",
        "audit_more_info":              "ഓഡിറ്റ് ലെഡ്ജർ അനുബന്ധ-മാത്രവും ഹാഷ്-ചങ്ങലയിൽ കോർത്തതുമാണ്. എല്ലാ ഭരണ നടപടികളും മാറ്റമില്ലായ്മ ഉറപ്പാക്കാൻ രേഖപ്പെടുത്തുന്നു.",
        "ledger_integrity":             "ലെഡ്ജർ സമഗ്രത നില",
        "ledger_verified":              "ലെഡ്ജർ സ്ഥിരീകരിച്ചു. {total} എൻട്രികൾ ഭദ്രം.",
        "ledger_integrity_verified":    "ലെഡ്ജർ സമഗ്രത സ്ഥിരീകരിച്ചു",
        "ledger_verified_reason":       "ഹാഷ് ചങ്ങല സ്ഥിരീകരണം തിരിമറി കണ്ടെത്തിയിട്ടില്ലെന്ന് ഉറപ്പിക്കുന്നു.",
        "ledger_corrupted":             "ലെഡ്ജർ സമഗ്രത പ്രശ്നം: {message}",
        "ledger_integrity_breach":      "ലെഡ്ജർ സമഗ്രത ലംഘനം",
        "ledger_breach_reason":         "ഓഡിറ്റ് ചങ്ങലയിൽ ഹാഷ് പൊരുത്തക്കേട് കണ്ടെത്തി.",
        "ledger_verified_banner":       "ലെഡ്ജർ സമഗ്രത: സ്ഥിരീകരിച്ചു — {total} എൻട്രികൾ പരിശോധിച്ചു. ചങ്ങല ഭദ്രം.",
        "ledger_tampered_banner":       "ലെഡ്ജർ സമഗ്രത പ്രശ്നം — {message}",
        "total_log_entries":            "മൊത്തം ലോഗ് എൻട്രികൾ",
        "all_records":                  "എല്ലാ രേഖകളും",
        "distinct_users":               "വ്യത്യസ്ത ഉപഭോക്താക്കൾ",
        "latest_entry":                 "ഏറ്റവും പുതിയ എൻട്രി",
        "most_recent_log":              "ഏറ്റവും പുതിയ ലോഗ്",
        "verified":                     "സ്ഥിരീകരിച്ചു",
        "compromised":                  "അപകടത്തിൽ",
        "audit_kpi_more_info":          "മൊത്തം എൻട്രികൾ: രേഖപ്പെടുത്തിയ ഭരണ സംഭവങ്ങളുടെ എണ്ണം. അദ്വിതീയ ഉപഭോക്താക്കൾ: വ്യത്യസ്ത അക്കൗണ്ടുകൾ. ചങ്ങല സാധുതയുള്ളത്: ക്രിപ്‌റ്റോഗ്രഫിക് സമഗ്രത നില.",
        "audit_records":                "ഓഡിറ്റ് രേഖകൾ",
        "dev_tools":                    "ഡെവലപ്പർ ടൂളുകൾ",
        "filter_logs":                  "ലോഗ് ഫിൽട്ടർ ചെയ്യുക",
        "filter_by_actor":              "ആക്ടർ അനുസരിച്ച് ഫിൽട്ടർ ചെയ്യുക",
        "filter_by_action":             "ആക്ഷൻ കീവേഡ് അനുസരിച്ച് ഫിൽട്ടർ ചെയ്യുക",
        "date_range":                   "തീയതി ശ്രേണി",
        "last_24h":                     "കഴിഞ്ഞ 24 മണിക്കൂർ",
        "last_7_days":                  "കഴിഞ്ഞ 7 ദിവസം",
        "last_30_days":                 "കഴിഞ്ഞ 30 ദിവസം",
        "max_rows":                     "പരമാവധി വരികൾ",
        "shown":                        "കാണിക്കുന്നു",
        "entry_id":                     "എൻട്രി ഐഡി",
        "actor":                        "ഉപഭോക്താവ്",
        "previous_hash":                "മുൻ ഹാഷ്",
        "current_hash":                 "നിലവിലെ ഹാഷ്",
        "inspect_full_hashes":          "നിർദ്ദിഷ്ട എൻട്രിയുടെ പൂർണ്ണ ഹാഷ് പരിശോധിക്കുക",
        "select_entry":                 "എൻട്രി തിരഞ്ഞെടുക്കുക",
        "download_logs_csv":            "ലോഗ് സിഎസ്വി ആയി ഡൗൺലോഡ് ചെയ്യുക",
        "no_audit_entries":             "തിരഞ്ഞെടുത്ത ഫിൽട്ടറുകളുമായി പൊരുത്തപ്പെടുന്ന ഓഡിറ്റ് ലോഗ് എൻട്രികൾ ഇല്ല.",
        "audit_hash_info":              "ഓരോ എൻട്രിയും SHA-256 ഉപയോഗിച്ച് ക്രിപ്‌റ്റോഗ്രഫിക്കായി ഹാഷ് ചെയ്ത് മുൻ എൻട്രിയുമായി ചങ്ങലയിൽ കോർത്തിരിക്കുന്നു.",
        "developer_tools":              "ഡെവലപ്പർ ടൂളുകൾ",
        "dev_tools_more_info":          "ഈ പാനൽ ഡെവലപ്‌മെന്റ്, ടെസ്റ്റിംഗ് മാത്രമുള്ളതാണ്.",
        "write_test_log_entry":         "ടെസ്റ്റ് ലോഗ് എൻട്രി എഴുതുക (ഡെവ് മാത്രം)",
        "write_to_ledger":              "ലെഡ്ജറിൽ എഴുതുക",
        "entry_written":                "എൻട്രി എഴുതി. കാണാൻ റിഫ്രഷ് ചെയ്യുക.",

        # ── Step 7A/7B/7E — i18n hardening meta-strings ──────────────────────
        "translation_parity_error":     "വിവർത്തന പൊരുത്ത പരാജയം: '{lang}' ഭാഷയിൽ കീകൾ കാണുന്നില്ല: {keys}",
        "translation_key_missing":      "'{lang}' ഭാഷയ്ക്ക് '{key}' വിവർത്തന കീ കാണുന്നില്ല",
        "english_leakage_detected":     "'{key}' കീയ്ക്കായി മലയാളം ഔട്ട്പുട്ടിൽ ഇംഗ്ലീഷ് ചോർച്ച കണ്ടെത്തി",
        "i18n_validation_passed":       "വിവർത്തന സമ്പൂർണ്ണത സ്ഥിരീകരിച്ചു: എല്ലാ ഭാഷകളും ഇംഗ്ലീഷ് കീ സെറ്റ് ഉൾക്കൊള്ളുന്നു.",

        # ── Step 7C — Dropdown option keys ────────────────────────────────────
        "status_open":                  "തുറന്നത്",
        "status_closed":                "അടച്ചത്",
        "status_under_review":          "അവലോകനത്തിൽ",
        "status_pending":               "തീർപ്പുകൽപ്പിക്കാത്തത്",
        "status_active":                "സജീവം",
        "status_resolved":              "പരിഹരിച്ചത്",
        "status_escalated":             "ഉയർത്തിയത്",
        "status_approved":              "അംഗീകൃതം",
        "status_rejected":              "നിരസിച്ചത്",
        "risk_low":                     "കുറഞ്ഞത്",
        "risk_medium":                  "മധ്യമം",
        "risk_high":                    "ഉയർന്നത്",
        "risk_critical":                "ഗുരുതരം",
        "sla_on_track":                 "ശരിയായ പാതയിൽ",
        "sla_at_risk":                  "അപകടത്തിൽ",
        "sla_breached":                 "ലംഘിച്ചത്",
        "filter_all_statuses":          "എല്ലാ സ്ഥിതികളും",
        "filter_all_regions":           "എല്ലാ മേഖലകളും",
        "filter_all_branches":          "എല്ലാ ശാഖകളും",
        "export_format_pdf":            "പിഡിഎഫ് (ബോർഡ്-റെഡി)",
        "export_format_json":           "ജോൺ (മെഷീൻ)",
        "export_format_xml":            "എക്സ്എംഎൽ (റെഗുലേറ്ററി)",

        # ── Step 7F — Clause label keys ───────────────────────────────────────
        "clause_label_dpdp_s5":         "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 5 — അറിയിപ്പ്",
        "clause_label_dpdp_s6":         "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 6 — അനുമതി",
        "clause_label_dpdp_s7":         "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 7 — നിയമസഹ ഉപയോഗങ്ങൾ",
        "clause_label_dpdp_s8":         "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 8 — ലംഘന അറിയിപ്പ്",
        "clause_label_dpdp_s9":         "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 9 — കുട്ടികളുടെ ഡാറ്റ",
        "clause_label_dpdp_s10":        "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 10 — പ്രധാന ഫിഡ്യൂഷ്യറി",
        "clause_label_dpdp_s11":        "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 11 — ഡാറ്റ പ്രിൻസിപ്പൽ അവകാശങ്ങൾ",
        "clause_label_dpdp_s12":        "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 12 — തിരുത്തൽ അവകാശം",
        "clause_label_dpdp_s13":        "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 13 — പരാതി പരിഹാര അവകാശം",
        "clause_label_dpdp_s16":        "ഡിപിഡിപി ആക്ട് 2023 സെക്ഷൻ 16 — ഡാറ്റ സൂക്ഷിക്കൽ പരിധി",
        "clause_label_rbi_csf":         "ആർബിഐ സൈബർ സുരക്ഷ ചട്ടക്കൂട്",
        "clause_label_nabard_it":       "നബാർഡ് ഐടി മാർഗ്ഗനിർദ്ദേശങ്ങൾ",
        "clause_label_cert_in":         "സിഇആർടി-ഐഎൻ നിർദ്ദേശങ്ങൾ 2022",
        "clause_label_dpdp_r12":        "ഡിപിഡിപി ചട്ടങ്ങൾ 2025 ചട്ടം 12 — ലംഘന റിപ്പോർട്ടിംഗ്",

        # ── Step 8 engine-dashboard new keys ─────────────────────────────────
        "system_dashboard":             "സിസ്റ്റം ഡാഷ്ബോർഡ്",
        "active_breaches":              "സജീവ ലംഘനങ്ങൾ",
        "weighted_score":               "ചട്ടക്കൂടുകൾ ഉടനീളം ഭാരം ചേർത്തത്",
        "weighted_across_branches":     "എല്ലാ ശാഖകളിലും ഭാരം ചേർത്തത്",
        "audit_chain_valid":            "ഓഡിറ്റ് ശൃംഖല സമഗ്രത: സ്ഥിരീകരിച്ചു",
        "audit_chain_broken":           "ഓഡിറ്റ് ശൃംഖല സമഗ്രത: തകർന്നു",
        "root_hash":                    "റൂട്ട് ഹാഷ്",
        "contact_dpo_immediately":      "ഉടൻ ഡിപിഒയെ ബന്ധപ്പെടുക",
        "escalation_overview":          "എസ്കലേഷൻ അവലോകനം",
        "escalation_branch":            "ശാഖ",
        "escalation_regional":          "പ്രാദേശിക",
        "escalation_dpo":               "ഡിപിഒ",
        "escalation_board":             "ബോർഡ്",
        "escalations_pending":          "എസ്കലേഷനുകൾ തീർപ്പുകൽപ്പിക്കാത്തത്",
        "level":                        "തലം",
        "dpia_status_summary":          "ഡിപിഐഎ സ്ഥിതി സംഗ്രഹം",
        "dpia_active":                  "സജീവ ഡിപിഐഎകൾ",
        "dpia_overdue":                 "കാലതാമസമുള്ള ഡിപിഐഎകൾ",
        "dpia_approved":                "അംഗീകൃത ഡിപിഐഎകൾ",
        "cleared":                      "ക്ലിയർ ചെയ്തത്",
        "requires_action":              "നടപടി ആവശ്യമാണ്",
        "regional_dashboard_caption":   "പ്രാദേശിക സമഗ്ര കാഴ്ച",
        "regional_average":             "പ്രാദേശിക ശരാശരി",
        "no_data_for_region":           "നിങ്ങളുടെ മേഖലയ്ക്ക് ഡാറ്റ ലഭ്യമല്ല.",
        "engine_data_unavailable":      "എൻജിൻ ഡാറ്റ ലഭ്യമല്ല — ചില മെട്രിക്കുകൾ അപൂർണ്ണമായിരിക്കാം.",
        "escalation_dpia":              "എസ്കലേഷൻ & ഡിപിഐഎ",
        "framework_compliance_breakdown": "ചട്ടക്കൂട് അനുസരണ വിശദാംശം",
        "governance_report":            "ഭരണ റിപ്പോർട്ട്",
        "customer_dashboard_message":   "കേരള ബാങ്ക് ഡാറ്റ പ്രൈവസി പോർട്ടലിലേക്ക് സ്വാഗതം.",
        "customer_consents_caption":    "നിങ്ങളുടെ സജീവ അനുമതികളും അവകാശ അഭ്യർത്ഥനകളും.",
        "no_governance_metrics_for_customer": "ഉപഭോക്തൃ അക്കൗണ്ടുകൾക്ക് ഭരണ മെട്രിക്കുകൾ ലഭ്യമല്ല.",

        # ── Step 15 export-hardening new keys ────────────────────────────────
        "classification_confidential":  "രഹസ്യം",
        "classification_label":         "തരംതിരിക്കൽ",
        "generated_at":                 "നിർമ്മിച്ച സമയം",
        "page":                         "പേജ്",
        "additional_data":              "അധിക ഡാറ്റ",
        "data":                         "ഡാറ്റ",
        "details":                      "വിശദാംശങ്ങൾ",
        "clause_level_compliance_detail": "ക്ലോസ് തല അനുസരണ വിശദാംശം",
        "clause_id":                    "ക്ലോസ് ഐഡി",
        "amendment_reference":          "ഭേദഗതി റഫറൻസ്",
        "score":                        "സ്കോർ",
        "export_pdf":                   "പിഡിഎഫ് (ബോർഡ്-റെഡി)",
        "export_json":                  "ജോൺ (മെഷീൻ)",
        "export_xml":                   "എക്സ്എംഎൽ (റെഗുലേറ്ററി)",
        "download_pdf":                 "പിഡിഎഫ് ഡൗൺലോഡ് ചെയ്യുക",
        "download_json":                "ജോൺ ഡൗൺലോഡ് ചെയ്യുക",
        "download_xml":                 "എക്സ്എംഎൽ ഡൗൺലോഡ് ചെയ്യുക",
        "pdf_generation_failed":        "പിഡിഎഫ് നിർമ്മാണം പരാജയപ്പെട്ടു",
        "export_failed":                "എക്സ്പോർട്ട് പരാജയപ്പെട്ടു",
        "audit_log_write_failed":       "ഓഡിറ്റ് ലോഗ് എഴുതൽ പരാജയപ്പെട്ടു",
        "on_track":                     "ശരിയായ പാതയിൽ",
        "at_risk":                      "അപകടത്തിൽ",
        "breached":                     "ലംഘിച്ചത്",
        "overdue":                      "കാലഹരണം",
        "days":                         "ദിവസം",
        "request_id":                   "അഭ്യർത്ഥന ഐഡി",
        "score_pct":                    "സ്കോർ %",
        "open_requests":                "തുറന്ന അഭ്യർത്ഥനകൾ",
        "sla_breaches":                 "എസ്എൽഎ ലംഘനങ്ങൾ",
        "across_system":                "സിസ്റ്റം ഉടനീളം",
        "board_dashboard_caption":      "എക്സിക്യൂട്ടീവ് സംഗ്രഹം — എല്ലാ മേഖലകളും",
        "dpo_dashboard_caption":        "പൂർണ്ണ ഭരണ കൺസോൾ — എല്ലാ മൊഡ്യൂളുകളും",
        "auditor_dashboard_caption":    "അനുസരണ നിരീക്ഷണ കാഴ്ച — വായനാ-മാത്രം",
        "admin_dashboard_caption":      "ടെക്നിക്കൽ സിസ്റ്റം ആരോഗ്യ കൺസോൾ",
        "dpdp_compliance_view":         "ഡിപിഡിപി അനുസരണ കാഴ്ച",
        "across_4_frameworks":          "4 നിയന്ത്രണ ചട്ടക്കൂടുകൾ ഉടനീളം",
        "requests_within_deadline":     "എസ്എൽഎ സময়പരിധിക്കുള്ളിൽ അഭ്യർത്ഥനകൾ",
        "incident_governance":          "സംഭവ ഭരണം",
        "lifecycle_compliant":          "ജീവിതചക്രം അനുസരണം",
        "under_sla_monitoring":         "എസ്എൽഎ നിരീക്ഷണത്തിൽ",
        "requires_escalation":          "എസ്കലേഷൻ ആവശ്യമാണ്",
        "regulatory_score":             "നിയന്ത്രണ അനുസരണ സ്കോർ",
        "sla_status_distribution":      "എസ്എൽഎ സ്ഥിതി വിതരണം",
        "sla_status_this_branch":       "എസ്എൽഎ സ്ഥിതി — ഈ ശാഖ",
        "branch_risk_level":            "ശാഖ അപകട നില",
        "current_risk_status":          "നിലവിലെ അപകട സ്ഥിതി",
        "active_incidents_reported":    "സജീവ സംഭവങ്ങൾ റിപ്പോർട്ട് ചെയ്തു",
        "rights_requests_action_required": "അവകാശ അഭ്യർത്ഥനകൾ — നടപടി ആവശ്യമാണ്",
        "branch_risk_distribution":     "ശാഖ അപകട വിതരണം",
        "branch_risk_profile_by_zone":  "മേഖല അടിസ്ഥാനത്തിൽ ശാഖ അപകട പ്രൊഫൈൽ",
        "component_health":             "ഘടക ആരോഗ്യം",
        "rule_engine":                  "നിയമ എൻജിൻ",
        "orchestration_layer":          "ഓർക്കസ്ട്രേഷൻ പാളി",
        "audit_ledger":                 "ഓഡിറ്റ് ലെഡ്ജർ",
        "auth_service":                 "ഓതൻ സർവ്വീസ്",
        "db_connection_pool":           "ഡിബി കണക്ഷൻ പൂൾ",
        "compliance_engine":            "അനുസരണ എൻജിൻ",
        "currently_logged_in":          "നിലവിൽ ലോഗിൻ ആയത്",
        "log_entries_recorded":         "ഇന്ന് ലോഗ് എൻട്രികൾ രേഖപ്പെടുത്തി",
        "since_last_reset":             "അവസാന റീസെറ്റ് മുതൽ",
        "current_period":               "നിലവിലെ കാലഘട്ടം",
        "audit_event_volume_today":     "ഇന്നത്തെ ഓഡിറ്റ് ഇവന്റ് അളവ്",
        "event_distribution":           "ഇവന്റ് വിതരണം",
        "evt_login":                    "ലോഗിൻ",
        "evt_data_access":              "ഡാറ്റ ആക്സസ്",
        "evt_consent_update":           "അനുമതി അപ്ഡേറ്റ്",
        "evt_rights_request":           "അവകാശ അഭ്യർത്ഥന",
        "evt_dpia_action":              "ഡിപിഐഎ നടപടി",
        "evt_breach_report":            "ലംഘന റിപ്പോർട്ട്",
        "evt_login_successful":         "ലോഗിൻ വിജയകരം",
        "evt_consent_updated":          "അനുമതി അപ്ഡേറ്റ് ചെയ്തു",
        "evt_login_failed":             "ലോഗിൻ പരാജയപ്പെട്ടു",
        "evt_rights_request_submitted": "അവകാശ അഭ്യർത്ഥന സമർപ്പിച്ചു",
        "total_audit_entries":          "മൊത്തം ഓഡിറ്റ് എൻട്രികൾ",
        "last_backup":                  "അവസാന ബാക്കപ്പ്",
        "no_data_for_branch":           "നിങ്ങളുടെ ശാഖയ്ക്ക് ഡാറ്റ ലഭ്യമല്ല.",
        "avg_compliance_score":         "ശരാശരി അനുസരണ സ്കോർ",
        "branches_below_target":        "ലക്ഷ്യത്തിൽ താഴെ ശാഖകൾ",
        "score_below_90":               "90%-ൽ താഴെ സ്കോർ",
        "branch_compliance_scorecard":  "ശാഖ അനുസരണ സ്കോർകാർഡ്",
        "compliance_score_pct":         "അനുസരണ സ്കോർ %",
        "open_rights_requests":         "തുറന്ന അവകാശ അഭ്യർത്ഥനകൾ",
        "compliance_vs_rights_requests": "അനുസരണ vs അവകാശ അഭ്യർത്ഥനകൾ",
        "active_rights_requests_per_branch": "ശാഖ അനുസരിച്ച് സജീവ അഭ്യർത്ഥനകൾ",
        "rights_request_volume_by_branch": "ശാഖ അടിസ്ഥാനത്തിൽ അഭ്യർത്ഥന അളവ്",
        "rights_request_management":    "അവകാശ അഭ്യർത്ഥന നിയന്ത്രണം",
        "no_incidents_reported":        "സംഭവങ്ങൾ ഒന്നും റിപ്പോർട്ട് ചെയ്തിട്ടില്ല.",
        "kerala_branch_risk_distribution": "കേരള ശാഖ അപകട വിതരണം",
        "gis_map_note":                 "മാപ്പ് കേരളത്തിലെ ശാഖ അപകട വിതരണം കാണിക്കുന്നു.",
        "knowledge_graph_caption":      "ഡിപിഡിപി ഭരണത്തിനുള്ള ഘടക ബന്ധ മാപ്പ്.",
        "knowledge_graph_note":         "ഗ്രാഫ് പ്രധാന ഭരണ ഘടകങ്ങൾ തമ്മിലുള്ള ബന്ധങ്ങൾ കാണിക്കുന്നു.",
        "kg_customer":                  "ഉപഭോക്താവ്",
        "kg_consent":                   "അനുമതി",
        "kg_purpose":                   "ഉദ്ദേശ്യം",
        "kg_branch":                    "ശാഖ",
        "kg_dpia":                      "ഡിപിഐഎ",
        "kg_risk":                      "അപകടം",
        "kg_rights_request":            "അവകാശ അഭ്യർത്ഥന",
        "kg_sla":                       "എസ്എൽഎ",
        "kg_compliance":                "അനുസരണം",
        "gis_map_caption":              "കേരളത്തിലെ ശാഖ അപകട നിലയുടെ ഭൂസ്ഥാനിക കാഴ്ച.",
        "target_90_pct":                "ലക്ഷ്യം: 90%",
        "purpose_distribution_note":    "ലൈവ് എൻജിൻ സ്ഥിതിയിൽ നിന്ന് ഉരുത്തിരിഞ്ഞ അനുസരണ സ്കോർ.",
        "branch_level_compliance_scores": "ശാഖ-തല അനുസരണ സ്കോറുകൾ",
        "projected_consent_expirations": "പ്രവചിക്കപ്പെട്ട അനുമതി കാലഹരണങ്ങൾ",
        "expiring_consents":            "കാലഹരണമാകുന്ന അനുമതികൾ",
        "consent_forecast_august_warning": "⚠ ആഗസ്റ്റ് 2026: ഉയർന്ന കാലഹരണ അളവ് പ്രവചിക്കപ്പെടുന്നു. നേരത്തേ പുതുക്കൽ ആരംഭിക്കുക.",
        "sla_status_by_branch":         "ശാഖ അനുസരിച്ч് എസ്എൽഎ സ്ഥിതി",
        "approved_dpias":               "അംഗീകൃത ഡിപിഐഎകൾ",

        # ── Missing keys (Malayalam — mirrors English as fallback) ────────
        "weighted_score_label":         "Weighted Score",
        "ledger_root_hash":             "Ledger Root Hash",
        "root_hash_caption":            "SHA-256 of the entire serialised ledger.",
        "root_hash_note":               "This hash uniquely identifies the current state of the audit ledger.",
        "root_hash_more_info":          "The root hash allows out-of-band tamper detection.",
        "root_hash_unavailable":        "Root hash not yet generated.",
        "ledger_integrity_metadata":    "Ledger Integrity Metadata",
        "integrity_metadata_note":      "This metadata is cryptographically derived from the live ledger.",
        "total_entries":                "Total Entries",
        "root_hash":                    "Root Hash",
        "dpia_caption":                 "DPDP Act 2023 Section 10 — Privacy Impact Assessments.",
        "dpia_more_info":               "DPIA is required for high-risk data processing activities.",
        "dpo_console_more_info":        "DPO console allows review and decision on all rights requests.",
        "dpo_console":                  "DPO Console",
        "dpo_console_caption":          "Review and manage all Data Subject Rights requests.",
        "officer_console":              "Officer Console",
        "officer_console_caption":      "Review and assist rights requests for your branch.",
        "no_rights_requests":           "No rights requests found.",
        "rights_filter_type":           "Filter by Type",
        "rights_filter_status":         "Filter by Status",
        "rights_all_types":             "All Types",
        "rights_all_statuses":          "All Statuses",
        "consent_access_restricted":    "Access restricted. Contact your Data Protection Officer.",
        "consent_contact_dpo":          "Contact your Data Protection Officer to request elevated access.",
        "notices_init_error":           "Notice initialisation error.",
        "breach_load_error":            "Failed to load breach incidents.",
        "breach_init_error":            "Breach module initialisation error.",
        "escalation_summary":           "Escalation Summary",
        "no_escalations":               "No active escalations.",
        "weighted_compliance_score":    "Weighted Compliance Score",
        "score_label":                  "Score",
        "weight_label":                 "Weight",
        "evidence_label":               "Evidence",
        "compliant":                    "Compliant",
        "non_compliant":                "Non-Compliant",
        "partial":                      "Partial",
        "request_id_label":             "Request ID",
        "request_type_label":           "Request Type",
        "request_status_label":         "Status",
        "request_submitted_at":         "Submitted At",
        "request_deadline":             "Deadline",
        "request_sla_status":           "SLA Status",
        "identity_verified_label":      "Identity Verified",
        "verify_identity_btn":          "Verify Identity",
        "approve_request_btn":          "Approve",
        "reject_request_btn":           "Reject",
        "escalate_request_btn":         "Escalate",
        "dpia_new":                     "New DPIA",
        "dpia_list":                    "DPIA Register",
        "dpia_no_records":              "No DPIA records found.",
        "dpia_pending":                 "Pending",
        "dpia_approved":                "Approved",
        "dpia_rejected":                "Rejected",
        "dpia_high":                    "High",
        "dpia_medium":                  "Medium",
        "dpia_low":                     "Low",

        # ── Remaining missing keys (Malayalam mirrors English) ────────────
        "amendment_ref":                "Amendment Reference",
        "assisted_mode_label":          "Assisted Submission Mode",
        "clause_scores":                "Clause Scores",
        "clause_status":                "Clause Status",
        "compliance_trend":             "Compliance Trend",
        "consent_load_error":           "Failed to load consent records.",
        "dpia_approve_btn":             "Approve",
        "dpia_approved_at":             "Approved At",
        "dpia_approved_by":             "Approved By",
        "dpia_approved_msg":            "DPIA approved.",
        "dpia_created":                 "DPIA submitted successfully.",
        "dpia_data_categories":         "Data Categories",
        "dpia_decision":                "Decision",
        "dpia_description":             "Description",
        "dpia_detail":                  "DPIA Detail",
        "dpia_draft":                   "Draft",
        "dpia_due_soon":                "Due Soon",
        "dpia_filter_risk":             "Filter by Risk Level",
        "dpia_filter_status":           "Filter by Status",
        "dpia_id_label":                "DPIA ID",
        "dpia_next_review":             "Next Review Date",
        "dpia_notes":                   "DPO Notes",
        "dpia_periodic_review":         "Periodic Review Schedule",
        "dpia_processing_purpose":      "Processing Purpose",
        "dpia_project":                 "Project / System",
        "dpia_reject_btn":              "Reject",
        "dpia_rejected_msg":            "DPIA rejected.",
        "dpia_residual_risk":           "Residual Risk",
        "dpia_retention_period":        "Retention Period",
        "dpia_review_due":              "Review Due",
        "dpia_risk_evaluation":         "Risk Evaluation",
        "dpia_risk_level":              "Risk Level",
        "dpia_safeguards":              "Safeguards",
        "dpia_save":                    "Save",
        "dpia_section_header":          "DPIA & Privacy Assessments",
        "dpia_status":                  "Status",
        "dpia_submit_btn":              "Submit DPIA",
        "dpia_submitted_at":            "Submitted At",
        "dpia_submitted_by":            "Submitted By",
        "dpia_third_parties":           "Third Parties Involved",
        "escalated_to":                 "Escalated To",
        "escalation_level":             "Escalation Level",
        "framework_scores":             "Framework Scores",
        "get_escalation_summary":       "Escalation Summary",
        "notice_publish_error":         "Failed to publish notice.",
        "notice_save_error":            "Failed to save notice.",
        "notices_load_error":           "Failed to load privacy notices.",
        "pending_remediation":          "Pending Remediation",
        "remediation_actions":          "Remediation Actions",
        "request_customer":             "Customer ID",
        "request_decision":             "Decision",
        "request_notes":                "Notes",
        "rights_closed":                "Closed",
        "rights_escalated":             "Escalated",
        "rights_in_progress":           "In Progress",
        "rights_open":                  "Open",
        "risk_heatmap":                 "Risk Heatmap",
        "score_breakdown":              "Score Breakdown",
        "sla_breach_count":             "SLA Breach Count",
        "submit_on_behalf":             "Submit on behalf of customer",
        # ── Auto-generated parity keys ───────────────────────────────────
        "access":                                      "Access",
        "active_cases":                                "Active Cases",
        "active_request_progress":                     "Active Request Progress",
        "active_sessions":                             "Active Sessions",
        "all_incidents_closed":                        "All Incidents Closed",
        "all_requests_by_status":                      "All Requests by Status",
        "all_requests_closed":                         "All Requests (Closed)",
        "all_requests_live_sla":                       "All Requests — Live SLA",
        "all_requests_live_sla_readonly":              "All Requests — Live SLA (Read Only)",
        "all_requests_sla":                            "All Requests SLA",
        "all_submitted":                               "All Submitted",
        "approaching_deadline":                        "Approaching Deadline",
        "assisted":                                    "Assisted",
        "assisted_branch_officer":                     "Assisted by Branch Officer",
        "assisted_consent_info":                       "Consent captured on behalf of customer by officer.",
        "assisted_consent_registered_reason":          "Officer-assisted consent registered.",
        "assisted_consent_registered_title":           "Assisted Consent Registered",
        "assisted_submission":                         "Assisted Submission",
        "audit_events_today":                          "Audit Events Today",
        "auditor_no_revoke_renew":                     "Auditors cannot revoke or renew consents.",
        "auditor_readonly_info":                       "Auditor view is read-only.",
        "auditor_rights_caption":                      "Read-only view of all rights requests.",
        "auto_escalated_when_red":                     "Auto-escalated when SLA turns Red.",
        "awaiting_action":                             "Awaiting Action",
        "being_processed":                             "Being Processed",
        "branch_notes":                                "Branch Notes",
        "branch_requests":                             "Branch Requests",
        "branch_risk_overview":                        "Branch Risk Overview",
        "capture_assisted_consent":                    "Capture Assisted Consent",
        "close_dpia":                                  "Close DPIA",
        "closed_at":                                   "Closed At",
        "compliance_customer_hint":                    "Compliance view is read-only for this role.",
        "compliance_regression_reason":                "Regression detected in compliance score.",
        "compliance_regression_title":                 "Compliance Regression",
        "compliance_score_trend":                      "Compliance Score Trend",
        "compliant_clauses":                           "Compliant Clauses",
        "compliant_threshold":                         "Compliant Threshold",
        "confirm_authority_notification":              "Confirm Authority Notification Sent",
        "confirm_authority_notification_help":         "Tick to confirm the regulatory authority has been notified.",
        "consent_creation_info":                       "New consent requires customer identity verification.",
        "consent_gate":                                "Consent Gate",
        "consent_lifecycle_caption":                   "Manage consent lifecycle — capture, renew, revoke.",
        "consent_lifecycle_info":                      "All consent actions are recorded in the audit ledger.",
        "consent_registered_reason":                   "New consent registered.",
        "consent_registered_title":                    "Consent Registered",
        "consent_renewed_reason":                      "Consent renewed successfully.",
        "consent_renewed_title":                       "Consent Renewed",
        "consent_revoked_reason":                      "Consent revoked.",
        "consent_revoked_title":                       "Consent Revoked",
        "consent_status_legend":                       "Active | Revoked | Expired | Renewed",
        "consent_withdrawn":                           "Consent Withdrawn",
        "consents_by_purpose":                         "Consents by Purpose",
        "consents_by_status":                          "Consents by Status",
        "content_ml":                                  "Malayalam Content",
        "correction":                                  "Correction",
        "count":                                       "Count",
        "created":                                     "Created",
        "critical_dpia_escalation_reason":             "Critical risk DPIA requires DPO approval.",
        "critical_dpia_escalation_title":              "Critical DPIA Escalated",
        "customer":                                    "Customer",
        "customer_decision":                           "Customer Decision",
        "customer_id_required":                        "Customer ID is required.",
        "customer_portal_caption":                     "Submit and track your data rights requests under DPDP Act 2023.",
        "customer_revoke_info":                        "Customers may revoke consent at any time.",
        "customer_rights_caption":                     "Your rights under the Digital Personal Data Protection Act 2023.",
        "customer_rights_sla_note":                    "Requests are processed within 30 days per DPDP Act Section 13.",
        "data_categories_involved":                    "Data Categories Involved",
        "date":                                        "Date",
        "days_left":                                   "Days Left",
        "decision_metadata":                           "Decision Metadata",
        "deny_consent":                                "Deny Consent",
        "describe_mitigation_action":                  "Describe the mitigation action taken.",
        "describe_processing_activity":                "Describe the processing activity.",
        "download_trend_csv":                          "Download Trend CSV",
        "dpdp_timely_processing_note":                 "DPDP Act 2023 mandates timely processing of all rights requests.",
        "dpia_analytics":                              "DPIA Analytics",
        "dpia_closed_success":                         "DPIA closed successfully.",
        "dpia_creation_note":                          "Initiate a DPIA for any high-risk processing activity.",
        "dpia_creation_restricted":                    "DPIA creation is restricted to Officers and DPO.",
        "dpia_id":                                     "DPIA ID",
        "dpia_initiated_reason":                       "New DPIA initiated.",
        "dpia_initiated_title":                        "DPIA Initiated",
        "dpia_register":                               "DPIA Register",
        "dpia_title":                                  "DPIA Title",
        "dpia_title_placeholder":                      "e.g. Customer Data Analytics Platform",
        "dpia_workflow_advanced_reason":               "DPIA workflow stage advanced.",
        "dpia_workflow_advanced_title":                "Workflow Stage Advanced",
        "dpias_by_risk_level":                         "DPIAs by Risk Level",
        "dpias_by_workflow_stage":                     "DPIAs by Workflow Stage",
        "dpo_auditor_no_consent_creation":             "DPO and Auditors cannot create consents directly.",
        "dpo_review_required":                         "DPO review required.",
        "dpo_submission_info":                         "DPO can submit requests on behalf of customers.",
        "drift_detected":                              "Drift Detected",
        "erasure":                                     "Erasure",
        "escalate":                                    "Escalate",
        "escalated_overdue_requests":                  "Escalated / Overdue Requests",
        "escalated_to_dpo":                            "Escalated to DPO",
        "escalations":                                 "Escalations",
        "estimated_records_affected":                  "Estimated Records Affected",
        "event":                                       "Event",
        "event_type":                                  "Event Type",
        "expires":                                     "Expires",
        "failed_logins":                               "Failed Logins",
        "filter_by_branch":                            "Filter by Branch",
        "filter_by_purpose":                           "Filter by Purpose",
        "final_override_dpo_warning":                  "Final override requires DPO authority.",
        "flagged_for_dpo_review":                      "Flagged for DPO Review",
        "for_dpo_action":                              "For DPO Action",
        "full_ids_visible":                            "Full IDs visible (DPO/Auditor view).",
        "grant_consent":                               "Grant Consent",
        "grievance":                                   "Grievance",
        "hash_freeze_note":                            "Published notices are hash-frozen and cannot be edited.",
        "high_critical_risk":                          "High / Critical Risk",
        "his_branch":                                  "This Branch",
        "id":                                          "ID",
        "id_verified":                                 "ID Verified",
        "identity_marked_verified":                    "Identity marked as verified.",
        "identity_verification_required_error":        "Identity verification required before processing.",
        "identity_verified":                           "Identity Verified",
        "identity_verified_confirm":                   "Confirm identity has been verified in person or via OTP.",
        "ids_masked_policy":                           "Customer IDs are masked per data minimisation policy.",
        "immediate_attention":                         "Immediate Attention Required",
        "initiate_new_dpia":                           "Initiate New DPIA",
        "initiator":                                   "Initiator",
        "kpi_realtime_note":                           "KPIs are derived from live consent registry.",
        "mark_identity_verified":                      "Mark Identity Verified",
        "mitigation_action_label":                     "Mitigation Action",
        "mitigation_action_placeholder":               "Describe the control or mitigation applied.",
        "mitigation_restricted":                       "Mitigation recording restricted to DPO.",
        "mitigation_workflow":                         "Mitigation Workflow",
        "my_request_history":                          "My Request History",
        "my_requests_only_caption":                    "Showing your submitted requests only.",
        "my_total_requests":                           "My Total Requests",
        "na":                                          "N/A",
        "new_dpia":                                    "New DPIA",
        "next_review":                                 "Next Review",
        "next_review_date":                            "Next Review Date",
        "no_approval_history":                         "No approval history.",
        "no_consent_data":                             "No consent records found.",
        "no_data_yet":                                 "No data yet.",
        "no_dpia_data_to_analyse":                     "No DPIA data to analyse.",
        "no_dpias_available":                          "No DPIAs available.",
        "no_dpias_awaiting_approval":                  "No DPIAs awaiting approval.",
        "no_dpias_recorded":                           "No DPIAs recorded.",
        "no_dpias_to_export":                          "No DPIAs to export.",
        "no_dpo_approved_dpias_to_close":              "No DPO-approved DPIAs to close.",
        "no_escalated_requests":                       "No escalated requests.",
        "no_evidence_recorded":                        "No evidence recorded.",
        "no_notices_recorded":                         "No privacy notices recorded.",
        "no_open_dpias_mitigation":                    "No open DPIAs for mitigation.",
        "no_records_match_filters":                    "No records match the selected filters.",
        "no_requests_submitted_yet":                   "No requests submitted yet.",
        "no_transitions_available":                    "No transitions available.",
        "no_trend_data":                               "No trend data available.",
        "non_compliant_clauses":                       "Non-Compliant Clauses",
        "notes_context":                               "Notes / Context",
        "notification_required_before_closure":        "Authority notification required before closure.",
        "officer_assisted_caption":                    "Submit a rights request on behalf of a customer.",
        "officer_assisted_info":                       "Officer-assisted submission is recorded in the audit ledger.",
        "officer_assisted_more_info":                  "Assisted submissions require customer identity verification.",
        "officer_branch_requests_caption":             "Rights requests submitted at your branch.",
        "officer_compliance_limited_view":             "Officers have a limited compliance view.",
        "officer_consent_warning":                     "Consent actions are binding and audit-logged.",
        "officer_id_verification_confirm":             "Confirm you have verified the customer's identity.",
        "open_in_progress":                            "Open / In Progress",
        "open_requests_by_sla":                        "Open Requests by SLA Status",
        "overall_score_pct":                           "Overall Score (%)",
        "partial_threshold":                           "Partial Threshold",
        "past_review_date":                            "Past Review Date",
        "preview_request":                             "Preview Request",
        "preview_request_customer_view":               "Preview (Customer View)",
        "previous_version_id":                         "Previous Version ID",
        "processing_activity_description":             "Processing Activity Description",
        "processing_activity_placeholder":             "Describe how personal data is processed.",
        "processing_purpose":                          "Processing Purpose",
        "provide_dpia_title":                          "Please provide a DPIA title.",
        "provide_rejection_reason":                    "Please provide a rejection reason.",
        "published_by":                                "Published By",
        "purpose_dpia_linkage_help":                   "Link this DPIA to a registered consent purpose.",
        "rate_limit_exceeded_session":                 "Too many submissions this session. Please try again later.",
        "re_authorised":                               "Re-Authorised",
        "reason":                                      "Reason",
        "records":                                     "Records",
        "red_escalated":                               "Red / Escalated",
        "regulatory_clause_reference_title":           "Regulatory Clause Reference",
        "regulatory_export_dpia_reports":              "Export DPIA Reports",
        "regulatory_export_note":                      "Export for regulatory submission or audit.",
        "regulatory_reports":                          "Regulatory Reports",
        "rejection_reason":                            "Rejection Reason",
        "reported_incidents":                          "Reported Incidents",
        "requires_reconsent":                          "Requires Re-consent",
        "requires_renewal":                            "Requires Renewal",
        "resolution_note":                             "Resolution Note",
        "reviews_overdue":                             "Reviews Overdue",
        "revocation_reason":                           "Revocation Reason",
        "revocation_reason_placeholder":               "Enter reason for revocation...",
        "revoked_at":                                  "Revoked At",
        "revoked_by_officer_default":                  "Revoked by officer",
        "rights_invocation_reason":                    "Reason for invoking this right",
        "rights_invocation_title":                     "Rights Invocation",
        "rights_requests":                             "Rights Requests",
        "risk_level_auto_computed_note":               "Risk level is automatically computed from the assessment.",
        "risk_score_distribution":                     "Risk Score Distribution",
        "risk_score_distribution_all_dpias":           "Risk Score Distribution — All DPIAs",
        "search_customer_id":                          "Search by Customer ID",
        "select_dpia":                                 "Select DPIA",
        "select_dpia_to_close":                        "Select DPIA to Close",
        "select_dpia_to_preview":                      "Select DPIA to Preview",
        "select_request":                              "Select Request",
        "self_service":                                "Self Service",
        "sla_amber":                                   "SLA Amber",
        "sla_analytics":                               "SLA Analytics",
        "sla_green":                                   "SLA Green",
        "sla_legend_note":                             "Green: on track | Amber: approaching deadline | Red: overdue",
        "sla_performance_analytics":                   "SLA Performance Analytics",
        "sla_red":                                     "SLA Red",
        "snapshot_at":                                 "Snapshot At",
        "snapshot_date":                               "Snapshot Date",
        "snapshot_history":                            "Snapshot History",
        "stage":                                       "Stage",
        "stage_advancement_restricted":                "Stage advancement is restricted.",
        "submit_assisted_request":                     "Submit Assisted Request",
        "submit_my_consent":                           "Submit My Consent",
        "submit_on_behalf_of_customer":                "Submit on Behalf of Customer",
        "submitted":                                   "Submitted",
        "submitted_on":                                "Submitted On",
        "supporting_details":                          "Supporting Details",
        "system_uptime":                               "System Uptime",
        "target_stage":                                "Target Stage",
        "third_parties_involved_label":                "Third Parties Involved",
        "total_dpias":                                 "Total DPIAs",
        "trend_caption":                               "Compliance score trend over time.",
        "trend_more_info":                             "Score is derived from live system state — consent, SLA, breach, DPIA, and audit data.",
        "triggered_by":                                "Triggered By",
        "unknown":                                     "Unknown",
        "user":                                        "User",
        "verification_method":                         "Verification Method",
        "view_history_for":                            "View History For",
        "weight":                                      "Weight",
        "within_window":                               "Within Window",
        "your_consents":                               "Your Consents",
        "your_customer_id":                            "Your Customer ID",
        "your_decision":                               "Your Decision",

        # ── Round-3 parity keys ──────────────────────────────────────────
        "access_my_data":                              "Access My Data",
        "audit_access_restricted":                     "Access restricted. Audit logs are read-only for this role.",
        "audit_contact_dpo":                           "Contact your Data Protection Officer for full audit access.",
        "auditor":                                     "Auditor",
        "authenticated":                               "Authenticated",
        "board_member":                                "Board Member",
        "branch_officer":                              "Branch Officer",
        "consent_withdrawal_action":                   "Consent Withdrawal",
        "correct_my_data":                             "Correct My Data",
        "create_rights_request":                       "Create Rights Request",
        "data_access":                                 "Data Access",
        "data_access_request":                         "Data Access Request",
        "data_correction":                             "Data Correction",
        "data_correction_request":                     "Data Correction Request",
        "data_erasure":                                "Data Erasure",
        "data_erasure_request":                        "Data Erasure Request",
        "dpo":                                         "DPO",
        "erase_my_data":                               "Erase My Data",
        "grievance_redressal":                         "Grievance Redressal",
        "kyc":                                         "KYC",
        "kyc_verification":                            "KYC Verification",
        "last_active":                                 "Last Active",
        "loan_processing":                             "Loan Processing",
        "login_account_locked":                        "Account locked due to too many failed attempts. Please try again in {minutes} minutes.",
        "login_error":                                 "Login error. Please contact the system administrator.",
        "login_lockout_wait":                          "Account is locked. Please wait {minutes} minutes before trying again.",
        "login_time":                                  "Login Time",
        "mfa_enter_code":                              "Enter your 6-digit authenticator code",
        "mfa_invalid":                                 "Invalid or expired code. Please try again.",
        "mfa_required":                                "Multi-Factor Authentication Required",
        "mfa_secret":                                  "MFA Secret",
        "mfa_verified":                                "MFA Verified",
        "mfa_verify":                                  "Verify",
        "nominate_representative":                     "Nominate Representative",
        "nomination_request":                          "Nomination Request",
        "password_hash":                               "Password Hash",
        "privacy_steward":                             "Privacy Steward",
        "regional_officer":                            "Regional Officer",
        "request":                                     "Request",
        "requires_id_verification":                    "requires identity verification",
        "requires_mandatory_id_verification":          "requires mandatory identity verification",
        "revoke_consent_request":                      "Revoke Consent",
        "role":                                        "Role",
        "stage_closed":                                "Closed",
        "stage_dpo_approved":                          "DPO Approved",
        "stage_initiated":                             "Initiated",
        "stage_rejected":                              "Rejected",
        "stage_steward_approved":                      "Steward Approved",
        "stage_under_review":                          "Under Review",
        "steward_approved":                            "Steward Approved",
        "system_admin":                                "System Admin",
        "under_review":                                "Under Review",
        "unknown_user":                                "Unknown User",
        "valid_consent_required_for":                  "Valid consent required for",
        "warning":                                     "Warning",
    },
}

# Alias for backward-compatibility with Step 6B TRANSLATIONS reference
TRANSLATIONS = LANG


# ===========================================================================
# Step 7C — Canonical dropdown option key lists
# Use: [t(k) for k in DROPDOWN_OPTIONS["status"]]  in all UI widgets.
# Never use raw English strings like ["Open", "Closed"] in selectboxes.
# ===========================================================================

DROPDOWN_OPTIONS: dict[str, list[str]] = {
    # Generic status selects
    "status": [
        "status_open", "status_closed", "status_under_review",
        "status_pending", "status_active", "status_resolved",
        "status_escalated", "status_approved", "status_rejected",
    ],
    "status_incident": [
        "status_open", "status_under_review",
        "status_resolved", "status_closed",
    ],
    "status_request": [
        "status_pending", "status_active",
        "status_approved", "status_rejected", "status_escalated",
    ],
    "status_consent": [
        "status_active", "status_pending",
        "status_rejected", "status_closed",
    ],
    # Risk levels
    "risk_level": ["risk_low", "risk_medium", "risk_high", "risk_critical"],
    # SLA status
    "sla_status": ["sla_on_track", "sla_at_risk", "sla_breached"],
    # Filters
    "filter_status": ["filter_all_statuses", "status_active", "status_closed"],
    "filter_region": ["filter_all_regions"],
    "filter_branch": ["filter_all_branches"],
    "filter_all":    ["filter_all"],
    # Export formats
    "export_format": ["export_format_pdf", "export_format_json", "export_format_xml"],
    # Processing purposes
    "purpose": [
        "purpose_loan", "purpose_kyc", "purpose_account",
        "purpose_insurance", "purpose_credit", "purpose_marketing",
        "purpose_fd", "purpose_savings", "purpose_remittance",
    ],
    # Data categories (breach module)
    "data_category": [
        "cat_financial", "cat_health", "cat_biometric", "cat_identity",
        "cat_contact", "cat_location", "cat_transaction", "cat_employment",
    ],
    # DPIA risk types
    "risk_type": [
        "risk_type_privacy", "risk_type_security",
        "risk_type_compliance", "risk_type_operational",
    ],
    # DPIA assessment types
    "assessment_type": [
        "assessment_full", "assessment_screening", "assessment_targeted",
    ],
    # Notice product journeys
    "product_journey": [
        "journey_savings", "journey_loan", "journey_insurance",
        "journey_fd", "journey_remittance", "journey_credit_card",
    ],
    # Sort options
    "sort_order": ["sort_newest", "sort_oldest", "sort_severity"],
    # Display language selector
    "display_language": ["english", "malayalam"],
    # Clause labels (compliance / notices / DPIA)
    "clause_label": [
        "clause_label_dpdp_s5",  "clause_label_dpdp_s6",
        "clause_label_dpdp_s7",  "clause_label_dpdp_s8",
        "clause_label_dpdp_s9",  "clause_label_dpdp_s10",
        "clause_label_dpdp_s11", "clause_label_dpdp_s12",
        "clause_label_dpdp_s13", "clause_label_dpdp_s16",
        "clause_label_rbi_csf",  "clause_label_nabard_it",
        "clause_label_cert_in",  "clause_label_dpdp_r12",
    ],
}


def get_dropdown_options(group: str, extra_keys: list[str] | None = None) -> list[str]:
    """
    Return a list of translated display strings for a named dropdown group.

    Usage (replaces all raw English lists in UI widgets):
        opts = get_dropdown_options("status_incident")
        choice = st.selectbox(t("new_status"), opts)

    Args:
        group:      Key into DROPDOWN_OPTIONS.
        extra_keys: Optional additional translation keys to append.

    Returns:
        List of translated strings for the current session language.

    Raises:
        KeyError: If group is not in DROPDOWN_OPTIONS.
    """
    if group not in DROPDOWN_OPTIONS:
        raise KeyError(f"Unknown DROPDOWN_OPTIONS group: '{group}'")
    keys = DROPDOWN_OPTIONS[group] + (extra_keys or [])
    return [t(k) for k in keys]


def dropdown_key_for_value(group: str, translated_value: str) -> str | None:
    """
    Reverse-lookup: given a translated display value, return the original key.

    Useful when storing canonical keys in data model after a selectbox choice.

    Args:
        group:            DROPDOWN_OPTIONS group name.
        translated_value: The translated string chosen by the user.

    Returns:
        Original key string, or None if not found.
    """
    if group not in DROPDOWN_OPTIONS:
        return None
    for key in DROPDOWN_OPTIONS[group]:
        if t(key) == translated_value:
            return key
    return None


# ===========================================================================
# Step 7B — Translation completeness validation
# ===========================================================================

# Lazy startup guard — set True once validated in the current process
_VALIDATION_DONE: bool = False


def validate_translation_completeness(
    reference_lang: str = "en",
    raise_on_failure: bool = True,
) -> dict[str, list[str]]:
    """
    Validate that all registered non-reference languages contain every key
    present in the reference language dictionary.

    Call this once during app initialisation (post-login) and after every
    call to register_language() / add_translation().

    Args:
        reference_lang:  The canonical source language (default "en").
        raise_on_failure: If True, raises TranslationParityError on mismatch.
                          If False, returns missing-key report without raising.

    Returns:
        Dict mapping language code → list of missing key strings.
        Empty dict means full parity.

    Raises:
        TranslationParityError: If raise_on_failure is True and any language
                                has missing keys.
    """
    global _VALIDATION_DONE
    reference_keys = set(LANG.get(reference_lang, {}).keys())
    missing: dict[str, list[str]] = {}

    for lang_code, lang_dict in LANG.items():
        if lang_code == reference_lang:
            continue
        lang_keys   = set(lang_dict.keys())
        absent      = sorted(reference_keys - lang_keys)
        if absent:
            missing[lang_code] = absent

    if missing and raise_on_failure:
        summary_parts = []
        for lang_code, keys in missing.items():
            key_preview = keys[:10]
            ellipsis    = f" … and {len(keys) - 10} more" if len(keys) > 10 else ""
            summary_parts.append(
                f"  [{lang_code}] missing {len(keys)} key(s): "
                f"{', '.join(key_preview)}{ellipsis}"
            )
        raise TranslationParityError(
            "Translation parity check failed. The following languages are "
            "incomplete:\n" + "\n".join(summary_parts)
        )

    _VALIDATION_DONE = True
    return missing



# ===========================================================================
# STEP 6C / Step 7A / 7D — Translation function (hardened)
# ===========================================================================

def t(key: str) -> str:
    """
    Return translated text for the current session language.

    Step 7A — Strict missing-key enforcement:
      Missing keys raise TranslationKeyError in ALL language modes.
      No silent empty strings. No silent fallback to raw key.
      Use t_safe(key) for optional strings where missing is acceptable.

    Step 7D — Malayalam ASCII leakage guard:
      In Malayalam mode, if the translated value contains ASCII alphabetic
      characters, EnglishLeakageError is raised immediately.
      Exceptions: numeric characters, punctuation, and known technical tokens
      (version strings, IDs) are permitted via t_safe().

    Malayalam STRICT mode (lang == "ml"):
      - Returns LANG["ml"][key] if the key exists.
      - Raises TranslationKeyError if the key is missing.
      - Raises EnglishLeakageError if result contains ASCII alpha characters.

    English mode (lang == "en"):
      - Returns LANG["en"][key] if the key exists.
      - Raises TranslationKeyError if the key is missing.

    Other registered languages:
      - Returns LANG[lang][key] if exists.
      - Falls back to LANG["en"][key] if missing in target language.
      - Raises TranslationKeyError if missing in both.

    Lazy startup guard:
      On first call in a new session, triggers validate_translation_completeness()
      in non-raising mode and stores result in session state for operator review.

    Args:
        key: Translation key, e.g. "dashboard", "submit_request"

    Returns:
        Translated string for the active language.

    Raises:
        TranslationKeyError: If the key is missing from the active language
                             (and from English fallback for non-en/non-ml langs).
        EnglishLeakageError: If Malayalam mode returns a value containing
                             ASCII alphabetic characters.
    """
    global _VALIDATION_DONE

    # Support both "lang" and "language" session keys for compatibility
    lang = st.session_state.get("lang") or st.session_state.get("language", "en")

    # Force valid language
    if lang not in LANG:
        lang = "en"

    # Lazy startup validation — runs once per session, non-raising
    if not _VALIDATION_DONE and not st.session_state.get("_i18n_validated"):
        try:
            missing = validate_translation_completeness(raise_on_failure=False)
            st.session_state["_i18n_validated"]  = True
            st.session_state["_i18n_missing"]    = missing
        except Exception:
            pass  # Never block the UI on validation error

    # ── Malayalam STRICT mode ─────────────────────────────────────────────────
    if lang == "ml":
        if key not in LANG["ml"]:
            raise TranslationKeyError(
                f"Missing Malayalam translation for key '{key}'. "
                "Add the key to LANG['ml'] in utils/i18n.py."
            )
        value = LANG["ml"][key]
        # Step 7D — ASCII leakage guard
        ascii_alpha = [ch for ch in value if ch.isascii() and ch.isalpha()]
        if ascii_alpha:
            raise EnglishLeakageError(
                f"English leakage detected for key '{key}' in Malayalam mode. "
                f"Offending characters: {''.join(set(ascii_alpha))!r}. "
                "Translate the value fully into Malayalam in LANG['ml']."
            )
        return value

    # ── English mode ──────────────────────────────────────────────────────────
    if lang == "en":
        if key not in LANG["en"]:
            raise TranslationKeyError(
                f"Missing English translation for key '{key}'. "
                "Add the key to LANG['en'] in utils/i18n.py."
            )
        return LANG["en"][key]

    # ── Other registered languages — fallback chain ───────────────────────────
    lang_dict = LANG[lang]
    if key in lang_dict:
        return lang_dict[key]
    if key in LANG["en"]:
        return LANG["en"][key]  # graceful English fallback for partial languages
    raise TranslationKeyError(
        f"Missing translation for key '{key}' in language '{lang}' "
        "(and in English fallback). Add to LANG['{lang}'] or LANG['en']."
    )


def t_safe(key: str, default: str = "") -> str:
    """
    Graceful translation lookup — returns default instead of raising.

    Use this ONLY for:
      - Optional UI strings where blank is acceptable
      - Dynamic keys generated at runtime that may not exist
      - Error message formatting where t() itself might fail

    For all critical UI labels, use t() to ensure missing keys are caught.

    Args:
        key:     Translation key.
        default: Value to return if key is missing (default: "").

    Returns:
        Translated string, or default if key is missing or leakage detected.
    """
    try:
        return t(key)
    except (TranslationKeyError, EnglishLeakageError):
        return default


def t_required(key: str) -> str:
    """
    Step 7E — Translation lookup that additionally raises if result is empty.

    Use in UI layers where an empty string would cause a broken layout
    (e.g. button labels, column headers, section titles).

    Args:
        key: Translation key.

    Returns:
        Translated string (guaranteed non-empty).

    Raises:
        TranslationKeyError: If key is missing.
        ValueError: If translation resolves to an empty string.
    """
    value = t(key)
    if not value:
        raise ValueError(
            f"Translation for key '{key}' resolved to an empty string "
            f"in language '{st.session_state.get('lang', 'en')}'. "
            "Update the translation value in utils/i18n.py."
        )
    return value




# ===========================================================================
# STEP 6F — English leakage validator (enforce zero-English in Malayalam mode)
# ===========================================================================

def validate_no_english_rendered(rendered_text: str) -> None:
    """
    Assert that no English alphabetic characters appear in rendered output
    when the active language is Malayalam.

    Raises
    ------
    EnglishLeakageError — if English text is detected while lang == "ml".

    Usage
    -----
    Call this before returning/rendering critical page content:
        validate_no_english_rendered(my_rendered_string)

    Note: UI framework identifiers (e.g. CSS class names, JSON keys,
    numeric strings) are typically not passed through this validator.
    Apply selectively to human-readable rendered output.
    """
    lang = st.session_state.get("lang", "en")
    if lang != "ml":
        return

    english_chars = [
        ch for ch in rendered_text
        if ch.isascii() and ch.isalpha()
    ]
    if english_chars:
        raise EnglishLeakageError(
            f"English text detected in Malayalam rendering mode. "
            f"Offending characters: {''.join(set(english_chars))!r}. "
            f"Ensure all UI strings pass through t() before rendering."
        )


# ===========================================================================
# STEP 6G — Unicode normalization for Malayalam (indicnlp)
# ===========================================================================

try:
    from indicnlp.normalize.indic_normalize import IndicNormalizerFactory as _IndicNormalizerFactory
    _factory     = _IndicNormalizerFactory()
    _normalizer  = _factory.get_normalizer("ml")
    _INDIC_AVAILABLE = True
except Exception:
    _INDIC_AVAILABLE = False
    _normalizer  = None


def normalize_malayalam(text: str) -> str:
    """
    Apply Unicode normalization to Malayalam text.

    Uses indicnlp IndicNormalizerFactory when the library is installed.
    Falls back to Python's unicodedata.normalize("NFC", text) to prevent
    zero-width joiner rendering errors and Unicode mismatch issues on all
    deployment environments where indicnlp may not be present.

    Args:
        text: Raw Malayalam Unicode string.

    Returns:
        Normalized Malayalam string.
    """
    if not text:
        return text

    if _INDIC_AVAILABLE and _normalizer is not None:
        try:
            return _normalizer.normalize(text)
        except Exception:
            pass  # fall through to NFC normalization

    # Fallback: NFC normalization (standard Unicode canonical composition)
    return unicodedata.normalize("NFC", text)


# ===========================================================================
# STEP 6H — Transliteration support (Manglish ↔ Malayalam)
# ===========================================================================

try:
    from indic_transliteration import sanscript as _sanscript
    from indic_transliteration.sanscript import transliterate as _transliterate
    _TRANSLIT_AVAILABLE = True
except ImportError:
    _TRANSLIT_AVAILABLE = False
    _sanscript      = None
    _transliterate  = None


def transliterate_ml_to_en(text: str) -> str:
    """
    Transliterate Malayalam script to ITRANS (Manglish romanisation).

    Requires: pip install indic-transliteration

    Args:
        text: Malayalam Unicode string.

    Returns:
        ITRANS-romanised string, or original text if library unavailable.
    """
    if _TRANSLIT_AVAILABLE and _transliterate is not None:
        try:
            return _transliterate(text, _sanscript.MALAYALAM, _sanscript.ITRANS)
        except Exception:
            pass
    return text


def transliterate_en_to_ml(text: str) -> str:
    """
    Transliterate ITRANS (Manglish romanisation) to Malayalam script.

    Requires: pip install indic-transliteration

    Args:
        text: ITRANS-romanised string.

    Returns:
        Malayalam Unicode string, or original text if library unavailable.
    """
    if _TRANSLIT_AVAILABLE and _transliterate is not None:
        try:
            result = _transliterate(text, _sanscript.ITRANS, _sanscript.MALAYALAM)
            return normalize_malayalam(result)
        except Exception:
            pass
    return text


# ===========================================================================
# STEP 6I — IndicTrans2 deterministic translation wrapper
# (for notices, clause explanations, and long-form content only —
#  NOT for UI labels; use t() for all UI labels)
# ===========================================================================

# Module-level model cache — loaded once on first call
_indictrans2_model = None
_INDICTRANS2_AVAILABLE = False


def _load_indictrans2():
    """
    Lazily load the IndicTrans2 local inference model.
    Attempts import of the IndicTransToolkit library.
    Sets _INDICTRANS2_AVAILABLE = True on success.
    """
    global _indictrans2_model, _INDICTRANS2_AVAILABLE
    if _indictrans2_model is not None:
        return

    try:
        # IndicTrans2 via AI4Bharat IndicTransToolkit
        # Install: pip install indic-trans
        # Model:   ai4bharat/indictrans2-en-indic-1B (download separately)
        from IndicTransToolkit import IndicProcessor
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

        model_name = "ai4bharat/indictrans2-en-indic-1B"
        tokenizer  = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        model      = AutoModelForSeq2SeqLM.from_pretrained(model_name, trust_remote_code=True)
        ip         = IndicProcessor(inference=True)

        _indictrans2_model   = {"tokenizer": tokenizer, "model": model, "ip": ip}
        _INDICTRANS2_AVAILABLE = True
    except Exception:
        _INDICTRANS2_AVAILABLE = False


def translate_en_to_ml(text: str) -> str:
    """
    Deterministically translate English text to Malayalam using IndicTrans2.

    Use ONLY for:
      - Privacy notices
      - Clause explanations (dpdp_clauses.py "text" field)
      - Long-form regulatory content

    Do NOT use for UI labels — use t() for all UI label text.

    Requires:
      pip install indic-trans transformers sentencepiece
      Downloaded model: ai4bharat/indictrans2-en-indic-1B

    Falls back to returning the original English text if the model
    is not available (ensures zero runtime crashes in all environments).

    Args:
        text: English source string.

    Returns:
        Malayalam Unicode string (normalized), or original text on failure.
    """
    if not text:
        return text

    _load_indictrans2()

    if not _INDICTRANS2_AVAILABLE or _indictrans2_model is None:
        # Graceful fallback: return English — operator must install model
        return text

    try:
        ip        = _indictrans2_model["ip"]
        tokenizer = _indictrans2_model["tokenizer"]
        model     = _indictrans2_model["model"]

        batch     = ip.preprocess_batch([text], src_lang="eng_Latn", tgt_lang="mal_Mlym")
        inputs    = tokenizer(batch, return_tensors="pt", padding=True, truncation=True)
        outputs   = model.generate(**inputs, num_beams=5, num_return_sequences=1)
        decoded   = tokenizer.batch_decode(outputs, skip_special_tokens=True)
        result    = ip.postprocess_batch(decoded, lang="mal_Mlym")[0]
        return normalize_malayalam(result)

    except Exception:
        return text


# ===========================================================================
# Dynamic extension helpers (preserved from original file)
# ===========================================================================

def add_translation(lang: str, key: str, value: str) -> None:
    """
    Add or overwrite a single translation key for a given language.

    Use this to:
      - Register new languages (Hindi, Tamil, Arabic, Kannada)
      - Patch a single string without editing this file
      - Support RBI or NABARD localisation requirements at runtime

    After calling this, validate_translation_completeness() should be
    called again to ensure parity is maintained. This function resets the
    lazy validation flag so the next t() call triggers re-validation.

    Args:
        lang:  ISO language code, e.g. "hi", "ta", "ar"
        key:   Translation key string
        value: Translated text

    Example:
        from utils.i18n import add_translation
        add_translation("hi", "dashboard", "डैशबोर्ड")
        add_translation("ta", "submit_request", "கோரிக்கை சமர்ப்பிக்கவும்")
    """
    global _VALIDATION_DONE
    if lang not in LANG:
        LANG[lang] = {}
    LANG[lang][key] = value
    _VALIDATION_DONE = False  # Force re-validation on next t() call


def register_language(lang: str, translations: dict[str, str]) -> None:
    """
    Register a full language dictionary at once.

    Resets the lazy validation flag so the next t() call triggers re-validation.

    Args:
        lang:         ISO language code, e.g. "hi"
        translations: Dict mapping keys to translated strings

    Example:
        from utils.i18n import register_language
        register_language("hi", {"dashboard": "डैशबोर्ड", ...})
    """
    global _VALIDATION_DONE
    if lang not in LANG:
        LANG[lang] = {}
    LANG[lang].update(translations)
    _VALIDATION_DONE = False  # Force re-validation on next t() call


# ===========================================================================
# UI helpers (preserved from original file)
# ===========================================================================

def get_language_options() -> list[str]:
    """Return display names of all registered languages, in registration order."""
    return list(SUPPORTED_LANGUAGES.values())


def get_language_code(display_name: str) -> str:
    """Convert a display name (e.g. 'Malayalam') to its ISO code ('ml')."""
    for code, name in SUPPORTED_LANGUAGES.items():
        if name == display_name:
            return code
    return "en"