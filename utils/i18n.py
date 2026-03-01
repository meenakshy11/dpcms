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

Architecture:
  t(key)                    — primary call for all UI text
  normalize_malayalam(text) — call after any Malayalam text is produced
  translate_en_to_ml(text)  — for notices / clause explanations only
  validate_no_english_rendered(text) — called before critical page renders

Malayalam STRICT mode:
  When lang == "ml", t() NEVER falls back to English.
  Missing keys return "" (empty string) instead.
  This enforces zero English leakage when Malayalam is selected.
"""

from __future__ import annotations

import unicodedata
import streamlit as st


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
    },
}

# Alias for backward-compatibility with Step 6B TRANSLATIONS reference
TRANSLATIONS = LANG


# ===========================================================================
# STEP 6C — Translation function (session-driven, STRICT Malayalam mode)
# ===========================================================================

def t(key: str) -> str:
    """
    Return translated text for the current session language.

    Malayalam STRICT mode (lang == "ml"):
      - Returns LANG["ml"][key] if the key exists.
      - Returns "" (empty string) if the key is missing.
      - NEVER falls back to English.
      - This ensures zero English leakage when Malayalam is selected.

    English mode (lang == "en" or any unregistered lang):
      - Returns LANG["en"][key] if the key exists.
      - Returns key (raw key) as last resort.

    Other registered languages:
      - Returns LANG[lang][key] if exists.
      - Falls back to LANG["en"][key], then key.

    Args:
        key: Translation key, e.g. "dashboard", "submit_request", "Status"

    Returns:
        Translated string for the active language.
    """
    # Support both "lang" and "language" session keys for compatibility
    lang = st.session_state.get("lang") or st.session_state.get("language", "en")

    # Force valid language
    if lang not in LANG:
        lang = "en"

    # Malayalam STRICT mode — no English fallback
    if lang == "ml":
        return LANG["ml"].get(key, "")

    # English mode
    if lang == "en":
        return LANG["en"].get(key, key)

    # Other registered languages — fallback to English, then raw key
    return LANG[lang].get(key) or LANG["en"].get(key) or key


# ===========================================================================
# STEP 6F — English leakage validator (enforce zero-English in Malayalam mode)
# ===========================================================================

def validate_no_english_rendered(rendered_text: str) -> None:
    """
    Assert that no English alphabetic characters appear in rendered output
    when the active language is Malayalam.

    Raises
    ------
    ValueError — if English text is detected while lang == "ml".

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
        raise ValueError(
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

    Args:
        lang:  ISO language code, e.g. "hi", "ta", "ar"
        key:   Translation key string
        value: Translated text

    Example:
        from utils.i18n import add_translation
        add_translation("hi", "dashboard", "डैशबोर्ड")
        add_translation("ta", "submit_request", "கோரிக்கை சமர்ப்பிக்கவும்")
    """
    if lang not in LANG:
        LANG[lang] = {}
    LANG[lang][key] = value


def register_language(lang: str, translations: dict[str, str]) -> None:
    """
    Register a full language dictionary at once.

    Args:
        lang:         ISO language code, e.g. "hi"
        translations: Dict mapping keys to translated strings

    Example:
        from utils.i18n import register_language
        register_language("hi", {"dashboard": "डैशबोर्ड", ...})
    """
    if lang not in LANG:
        LANG[lang] = {}
    LANG[lang].update(translations)


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