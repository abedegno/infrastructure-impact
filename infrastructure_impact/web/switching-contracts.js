/* Strict public study contracts. No network, runtime dependencies, or permissive fallback. */
(() => {
  // Generated from packaged schemas/definition by checks/generate_switching_contracts.py.
  // prettier-ignore
  const bundle = /* BEGIN GENERATED CONTRACTS */ {"schemas":{"switching-study-v1.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"type":"integer","const":1},"id":{"const":"campus-branch-switching"},"version":{"type":"integer","minimum":1},"start_date":{"type":"string","format":"date"},"cutoff_date":{"type":"string","format":"date"},"targets":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","minLength":1,"pattern":"\\S"},"vendor":{"enum":["cisco","aruba","arista"]},"family":{"enum":["cisco-iosxe","aruba-aoscx","arista-eos"]},"models":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"minItems":1,"uniqueItems":true},"aliases":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"literal":{"type":"string","minLength":1,"pattern":"\\S"},"model":{"type":"string","minLength":1,"pattern":"\\S"},"source_url":{"type":"string","format":"uri","pattern":"^https://"},"source_locator":{"type":"string","minLength":1,"pattern":"\\S"}},"required":["literal","model","source_url","source_locator"]},"uniqueItems":true},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true}},"required":["id","vendor","family","models","aliases","issues"]},"minItems":1,"uniqueItems":true},"references":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","minLength":1,"pattern":"\\S"},"vendor":{"enum":["cisco","aruba","arista"]},"source_url":{"type":"string","format":"uri","pattern":"^https://"},"source_locator":{"type":"string","minLength":1,"pattern":"\\S"},"reviewed_at":{"type":"string","format":"date"},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true}},"required":["id","vendor","source_url","source_locator","reviewed_at","issues"]},"minItems":1,"uniqueItems":true}},"required":["schema_version","id","version","start_date","cutoff_date","targets","references"],"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-study:1","title":"Source-bound campus and branch switching study v1"},"switching-evidence-v1.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"type":"integer","const":1},"publication":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"type":"integer","const":2}},"required":["id","advisory_schema_version"]},{"type":"null"}]},"generated_at":{"type":"string","format":"date-time"},"definition_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"claims":{"type":"array","items":{"$ref":"#/$defs/claim"}},"coverage":{"type":"array","items":{"$ref":"#/$defs/coverage"}},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"score_availability":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"vendor":{"enum":["cisco","aruba","arista"]},"advisory_id":{"type":"string","minLength":1},"source_url":{"type":"string","format":"uri"},"source":{"anyOf":[{"$ref":"#/$defs/source"},{"type":"null"}]},"cve_id":{"type":["string","null"],"pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"product_id":{"type":["string","null"]},"context":{"enum":["study_claim","source_only_unclassified"]},"state":{"enum":["available","unavailable","incomplete","invalid"]},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"attempts":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"source":{"enum":["cve_record","nvd"]},"cve_id":{"type":["string","null"]},"state":{"enum":["unknown","ok","rate_limited","source_missing","invalid_record","network_error","request_state_unresolved"]},"checked_at":{"type":["string","null"],"format":"date-time"},"retry_at":{"type":["string","null"],"format":"date-time"}},"required":["source","cve_id","state","checked_at","retry_at"]}}},"required":["vendor","advisory_id","source_url","source","cve_id","product_id","context","state","issues","attempts"]}}},"required":["schema_version","publication","generated_at","definition_sha256","claims","coverage","issues"],"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-evidence:1","title":"Source-bound switching evidence v1","$defs":{"source":{"type":"object","additionalProperties":false,"properties":{"source_url":{"type":"string","format":"uri","pattern":"^https://"},"source_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"retrieved_at":{"type":"string","format":"date-time"},"source_locator":{"type":"string","minLength":1,"pattern":"\\S"}},"required":["source_url","source_sha256","retrieved_at","source_locator"]},"platform_binding":{"type":"object","additionalProperties":false,"properties":{"platform":{"type":"string","minLength":1,"pattern":"\\S"},"model":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"basis":{"enum":["publisher_explicit","reviewed_alias","unresolved"]},"source":{"anyOf":[{"$ref":"#/$defs/source"},{"type":"null"}]}},"required":["platform","model","basis","source"]},"remediation":{"type":"object","additionalProperties":false,"properties":{"publisher_id":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"category":{"type":"string","minLength":1,"pattern":"\\S"},"details":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"product_ids":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true,"description":"Explicit publisher product identifiers. Empty lists or an unknown enclosing product require remediation_product_scope_unresolved and do not establish product-specific remediation evidence."},"version_expressions":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true},"published_availability":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}],"description":"Literal publisher availability statement, independent of availability_date. Null requires availability_statement_missing in the enclosing claim issues."},"availability_date":{"anyOf":[{"anyOf":[{"type":"string","format":"date"},{"type":"string","format":"date-time"}]},{"type":"null"}],"description":"Explicitly published availability date; never derived from an availability statement. Null requires availability_date_missing in the enclosing claim issues."},"source":{"$ref":"#/$defs/source"},"scope_binding":{"type":"object","additionalProperties":false,"properties":{"basis":{"enum":["same_source_row","reviewed_source_sections"]},"cve_id":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"},"source":{"$ref":"#/$defs/source"},"fixed_product":{"const":"Arista EOS"},"fixed_source":{"$ref":"#/$defs/source"}},"required":["basis","cve_id","source"],"description":"Explicit reviewed linkage: same source row, or the exact reviewed Arista 0100 EOS affected and CVE-specific Resolution sections. Never establishes a model or availability date.","allOf":[{"if":{"properties":{"basis":{"const":"reviewed_source_sections"}}},"then":{"required":["fixed_product","fixed_source"]},"else":{"not":{"anyOf":[{"required":["fixed_product"]},{"required":["fixed_source"]}]}}}]},"availability":{"enum":["vendor_reports_fixed","planned","partial_mitigation","unavailable","no_fix_planned","not_a_fix","unknown"],"description":"Source-led classification separate from literal published_availability. Absent means unknown; never derive an availability date."}},"required":["publisher_id","category","details","product_ids","version_expressions","published_availability","availability_date","source"]},"bundle":{"type":"object","additionalProperties":false,"properties":{"publisher_id":{"type":"string","minLength":1,"pattern":"\\S"},"title":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"member_advisory_ids":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"minItems":1,"uniqueItems":true},"published_at":{"anyOf":[{"anyOf":[{"type":"string","format":"date"},{"type":"string","format":"date-time"}]},{"type":"null"}]},"source":{"$ref":"#/$defs/source"}},"required":["publisher_id","title","member_advisory_ids","published_at","source"]},"score":{"type":"object","additionalProperties":false,"properties":{"system":{"type":"string","minLength":1,"pattern":"\\S"},"version":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"value":{"anyOf":[{"type":"number","minimum":0,"maximum":10},{"type":"null"}]},"vector":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"severity":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"cve_id":{"anyOf":[{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"},{"type":"null"}]},"product_ids":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true},"scope":{"enum":["cve_specific","bulletin_shared","unresolved"]},"source":{"$ref":"#/$defs/source"},"provider":{"type":["string","null"]},"origin":{"enum":["vendor_advisory","cve_record","nvd"]},"applicability":{"enum":["source_product","cve_level"]},"revision":{"type":["string","null"]},"validation":{"enum":["valid","incomplete"]},"issues":{"type":"array","items":{"type":"string"},"uniqueItems":true},"context":{"type":"array","items":{"type":"string"},"uniqueItems":true},"preferred":{"type":"boolean"},"product_context":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"product_id":{"type":"string"},"product":{"type":["string","null"]},"source_locator":{"type":"string"},"version_expressions":{"type":"array","items":{"type":"string"},"uniqueItems":true},"issues":{"type":"array","items":{"type":"string"},"uniqueItems":true}},"required":["product_id","product","source_locator","version_expressions","issues"]}},"vector_group":{"enum":["CVSS-B","CVSS-BT","CVSS-BE","CVSS-BTE","reported_base_with_optional_context"]}},"required":["system","version","value","vector","severity","cve_id","product_ids","scope","source"]},"claim":{"type":"object","additionalProperties":false,"properties":{"claim_id":{"type":"string","pattern":"^[a-f0-9]{64}$"},"vendor":{"enum":["cisco","aruba","arista"]},"advisory_id":{"type":"string","minLength":1,"pattern":"\\S"},"cve_id":{"anyOf":[{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"},{"type":"null"}]},"product_id":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"product":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"revision":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"source":{"$ref":"#/$defs/source"},"publisher":{"type":"object","additionalProperties":false,"properties":{"id":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"sequence":{"anyOf":[{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"integer","minimum":-9007199254740991,"maximum":9007199254740991}]},{"type":"null"}]},"status":{"anyOf":[{"type":"string","minLength":1,"pattern":"\\S"},{"type":"null"}]},"source":{"$ref":"#/$defs/source"}},"required":["id","sequence","status"]},"initial_published_at":{"anyOf":[{"anyOf":[{"type":"string","format":"date"},{"type":"string","format":"date-time"}]},{"type":"null"}]},"updated_at":{"anyOf":[{"anyOf":[{"type":"string","format":"date"},{"type":"string","format":"date-time"}]},{"type":"null"}]},"family":{"anyOf":[{"enum":["cisco-iosxe","aruba-aoscx","arista-eos"]},{"type":"null"}]},"named_platforms":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true},"platform_bindings":{"type":"array","items":{"$ref":"#/$defs/platform_binding"},"uniqueItems":true},"status":{"enum":["affected","unaffected","fixed","partially_mitigated","investigating","unknown","recommended","conflicting"]},"scope":{"enum":["cve_specific","bulletin_shared","unresolved"]},"scope_level":{"enum":["os_family","model_qualified"]},"version_expressions":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true},"conditions":{"type":"array","items":{"type":"string","minLength":1,"pattern":"\\S"},"uniqueItems":true},"remediations":{"type":"array","items":{"$ref":"#/$defs/remediation"},"uniqueItems":true},"bundle":{"anyOf":[{"$ref":"#/$defs/bundle"},{"type":"null"}]},"scores":{"type":"array","items":{"$ref":"#/$defs/score"},"uniqueItems":true},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"vendor_severity":{"type":"array","items":{"$ref":"#/$defs/vendor_severity"}},"conditional_affected":{"type":["boolean","null"],"description":"True only for an explicit reviewed prerequisite; false only for an explicit unrestricted publisher statement; null or absent is unclassified."}},"required":["claim_id","vendor","advisory_id","cve_id","product_id","product","revision","source","publisher","initial_published_at","updated_at","family","named_platforms","platform_bindings","status","scope","scope_level","version_expressions","conditions","remediations","bundle","scores","issues"]},"coverage":{"type":"object","additionalProperties":false,"properties":{"vendor":{"enum":["cisco","aruba","arista"]},"source_url":{"type":"string","format":"uri","pattern":"^https://"},"state":{"enum":["complete","partial","unavailable","unstable","unknown"]},"observed_start":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"observed_end":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"total":{"anyOf":[{"type":"integer","minimum":0},{"type":"null"}]},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"enumeration":{"type":"object","additionalProperties":false,"properties":{"definition_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"source_kind":{"enum":["openvuln","index","listing",null]},"window":{"type":"object","additionalProperties":false,"properties":{"start_date":{"type":"string","format":"date"},"end_date":{"type":"string","format":"date"}},"required":["start_date","end_date"]},"coverage_state":{"enum":["not_configured","unstable","blocked","enumerated","partial"]},"portfolio_completeness":{"const":"not_established"},"gaps":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"expected_total":{"type":["integer","null"],"minimum":0},"discovered_unique_identities":{"type":["integer","null"],"minimum":0},"duplicate_entries":{"type":["integer","null"],"minimum":0},"withdrawn_entries":{"type":["integer","null"],"minimum":0},"retrieved":{"type":["integer","null"],"minimum":0},"parsed":{"type":["integer","null"],"minimum":0},"parse_failed":{"type":["integer","null"],"minimum":0},"retrieval_failed":{"type":["integer","null"],"minimum":0},"classified":{"type":["integer","null"],"minimum":0},"classification_pending":{"type":["integer","null"],"minimum":0},"unknown_dates":{"type":["integer","null"],"minimum":0},"unknown_models":{"type":["integer","null"],"minimum":0},"exhausted_errors":{"type":["integer","null"],"minimum":0}},"required":["definition_sha256","source_kind","window","coverage_state","portfolio_completeness","gaps","expected_total","discovered_unique_identities","duplicate_entries","withdrawn_entries","retrieved","parsed","parse_failed","retrieval_failed","classified","classification_pending","unknown_dates","unknown_models","exhausted_errors"],"description":"Optional allowlisted Task3 manifest facts for this source window, never per-period attribution or historical portfolio completeness."}},"required":["vendor","source_url","state","observed_start","observed_end","total","issues"]},"vendor_severity":{"type":"object","additionalProperties":false,"properties":{"vendor":{"enum":["cisco","aruba","arista"]},"advisory_id":{"type":"string","minLength":1},"rating":{"type":"string","minLength":1,"maxLength":4000},"scheme":{"type":["string","null"]},"namespace":{"type":["string","null"]},"scope":{"const":"advisory"},"cve_id":{"type":"null"},"product_ids":{"type":"array","maxItems":0},"source":{"$ref":"#/$defs/source"},"revision":{"type":["string","null"]},"issues":{"type":"array","items":{"type":"string"},"uniqueItems":true}},"required":["vendor","advisory_id","rating","scheme","namespace","scope","cve_id","product_ids","source","revision","issues"]}}},"switching-comparison-v1.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"type":"integer","const":1},"publication":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"type":"integer","const":2}},"required":["id","advisory_schema_version"]},{"type":"null"}]},"generated_at":{"type":"string","format":"date-time"},"evaluated_at":{"type":"string","format":"date-time"},"definition":{"$ref":"urn:infrastructure-impact:switching-study:1"},"selection":{"type":"object","additionalProperties":false,"properties":{"requested_vendor":{"anyOf":[{"enum":["cisco","aruba","arista"]},{"type":"null"}]},"effective_vendors":{"type":"array","items":{"enum":["cisco","aruba","arista"]},"uniqueItems":true},"scope_level":{"enum":["os_family","model_qualified"]},"requested_window":{"type":"string","pattern":"^(all|pre|post|undated|[0-9]{4})$"},"effective_windows":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"requested_cve_ids":{"anyOf":[{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},{"type":"null"}]},"effective_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"definition_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"required":["requested_vendor","effective_vendors","scope_level","requested_window","effective_windows","requested_cve_ids","effective_cve_ids","definition_sha256"]},"rows":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"row_id":{"type":"string","minLength":1},"vendor":{"enum":["cisco","aruba","arista"]},"scope_level":{"enum":["os_family","model_qualified"]},"window":{"type":"string","pattern":"^(all|pre|post|undated|[0-9]{4})$"},"period_start":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"period_end":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"date_basis":{"const":"initial_publisher_date_utc_day"},"event_date_basis":{"const":"explicit_bundle_initial_else_advisory_initial"},"advisory_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"claim_ids":{"type":"array","items":{"type":"string","pattern":"^[a-f0-9]{64}$"},"uniqueItems":true},"affected_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"conditional_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"event_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"events":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"event_id":{"type":"string","minLength":1},"kind":{"enum":["bundle","unbundled"]},"publisher_id":{"type":"string","minLength":1},"published_at":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"claim_ids":{"type":"array","items":{"type":"string","pattern":"^[a-f0-9]{64}$"},"uniqueItems":true},"advisory_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"issues":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true}},"required":["event_id","kind","publisher_id","published_at","claim_ids","advisory_ids","cve_ids","issues"]},"uniqueItems":true},"counts":{"type":"object","additionalProperties":false,"properties":{"advisories":{"type":"integer","minimum":0},"cves":{"type":"integer","minimum":0},"claims":{"type":"integer","minimum":0},"affected_cves":{"type":"integer","minimum":0},"conditional_cves":{"type":"integer","minimum":0},"draft_advisories":{"type":"integer","minimum":0},"remediation_events":{"type":"integer","minimum":0},"bundled_events":{"type":"integer","minimum":0},"unbundled_publications":{"type":"integer","minimum":0},"fixed_only_claims":{"type":"integer","minimum":0},"planned_fix_claims":{"type":"integer","minimum":0},"workaround_claims":{"type":"integer","minimum":0},"model_unresolved_claims":{"type":"integer","minimum":0},"conditionality_unclassified_cves":{"type":"integer","minimum":0},"affected_advisories":{"type":"integer","minimum":0}},"required":["advisories","cves","claims","affected_cves","conditional_cves","draft_advisories","remediation_events","bundled_events","unbundled_publications","fixed_only_claims","planned_fix_claims","workaround_claims","model_unresolved_claims","conditionality_unclassified_cves","affected_advisories"]},"status_buckets":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"status":{"enum":["affected","unaffected","fixed","investigating","unknown","partially_mitigated","recommended","conflicting"]},"scope":{"enum":["cve_specific","bulletin_shared","unresolved"]},"claim_ids":{"type":"array","items":{"type":"string","pattern":"^[a-f0-9]{64}$"},"uniqueItems":true},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["status","scope","claim_ids","cve_ids","count"]},"uniqueItems":true},"severity":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"version":{"anyOf":[{"enum":["2.0","3.0","3.1","4.0"]},{"type":"null"}]},"provider":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"origin":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"preferred":{"anyOf":[{"type":"boolean"},{"type":"null"}]},"band":{"enum":["None","Low","Medium","High","Critical","Unknown"]},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["version","provider","origin","preferred","band","cve_ids","count"]},"uniqueItems":true},"vendor_severity":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"rating":{"type":"string","minLength":1},"scheme":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"namespace":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"scope":{"const":"advisory"},"advisory_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["rating","scheme","namespace","scope","advisory_ids","count"]},"uniqueItems":true},"kev":{"type":"object","additionalProperties":false,"properties":{"availability":{"enum":["available","missing","disabled","failed","stale","future","not_configured"]},"listed_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"unknown_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"listed_count":{"type":"integer","minimum":0},"unknown_count":{"type":"integer","minimum":0},"denominator":{"type":"integer","minimum":0}},"required":["availability","listed_cve_ids","unknown_cve_ids","listed_count","unknown_count","denominator"]},"coverage":{"type":"object","additionalProperties":false,"properties":{"state":{"enum":["partial","unknown"]},"expected_advisories":{"type":"null"},"observed_advisories":{"type":"integer","minimum":0},"basis":{"const":"retained_source_windows_not_period_completeness"},"sources":{"type":"array","items":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/$defs/coverage"},"uniqueItems":true}},"required":["state","expected_advisories","observed_advisories","basis","sources"]},"denominators":{"type":"object","additionalProperties":false,"properties":{"affected_cves":{"type":"integer","minimum":0},"observed_advisories":{"type":"integer","minimum":0},"expected_advisories":{"type":"null"}},"required":["affected_cves","observed_advisories","expected_advisories"]},"issues":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"affected_advisory_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true}},"required":["row_id","vendor","scope_level","window","period_start","period_end","date_basis","event_date_basis","advisory_ids","cve_ids","claim_ids","affected_cve_ids","conditional_cve_ids","event_ids","events","counts","status_buckets","severity","vendor_severity","kev","coverage","denominators","issues","affected_advisory_ids"]},"uniqueItems":true},"sources":{"type":"array","items":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/$defs/source"},"uniqueItems":true},"issues":{"type":"array","items":{"type":"string","pattern":"^[a-z][a-z0-9_]*$"},"uniqueItems":true},"method":{"type":"string","minLength":1,"pattern":"\\S"},"availability":{"enum":["available","unavailable"]},"observation_end":{"type":"string","format":"date"},"inputs":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"evidence":{"$ref":"urn:infrastructure-impact:switching-evidence:1"},"kev":{"$ref":"urn:infrastructure-impact:kev:1"}},"required":["evidence","kev"]},{"type":"null"}]}},"required":["schema_version","publication","generated_at","evaluated_at","definition","selection","rows","sources","issues","method","availability","observation_end","inputs"],"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-comparison:1","title":"Descriptive switching comparison v1"},"switching-summary-v1.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/schema_version"},"publication":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/publication"},"generated_at":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/generated_at"},"evaluated_at":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/evaluated_at"},"definition":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/definition"},"selection":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/selection"},"rows":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/rows"},"sources":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/sources"},"issues":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/issues"},"method":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/method"},"availability":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/availability"},"observation_end":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/observation_end"},"representation":{"const":"summary"}},"required":["schema_version","publication","generated_at","evaluated_at","definition","selection","rows","sources","issues","method","availability","observation_end","representation"],"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-summary:1","title":"Explicit switching comparison summary v1"},"switching-inputs-v1.json":{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-inputs:1","title":"Strict sharded switching input metadata v1","type":"object","additionalProperties":false,"required":["representation","evidence","kev"],"properties":{"representation":{"const":"switching-inputs"},"evidence":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/properties/schema_version"},"publication":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/properties/publication"},"generated_at":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/properties/generated_at"},"definition_sha256":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/properties/definition_sha256"},"issues":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/properties/issues"}},"required":["schema_version","publication","generated_at","definition_sha256","issues"]},"kev":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"$ref":"urn:infrastructure-impact:kev:1#/properties/schema_version"},"publication":{"$ref":"urn:infrastructure-impact:kev:1#/properties/publication"},"generated_at":{"$ref":"urn:infrastructure-impact:kev:1#/properties/generated_at"},"evaluated_at":{"$ref":"urn:infrastructure-impact:kev:1#/properties/evaluated_at"},"source":{"$ref":"urn:infrastructure-impact:kev:1#/properties/source"},"catalogue":{"$ref":"urn:infrastructure-impact:kev:1#/properties/catalogue"},"policy":{"$ref":"urn:infrastructure-impact:kev:1#/properties/policy"},"listed_cve_ids":{"$ref":"urn:infrastructure-impact:kev:1#/properties/listed_cve_ids"},"selection":{"$ref":"urn:infrastructure-impact:kev:1#/properties/selection"}},"required":["schema_version","publication","generated_at","evaluated_at","source","catalogue","policy","listed_cve_ids","selection"]}}},"kev-v1.json":{"type":"object","additionalProperties":false,"required":["schema_version","publication","generated_at","evaluated_at","source","catalogue","policy","listed_cve_ids","entries","selection"],"properties":{"schema_version":{"const":1,"type":"integer"},"publication":{"anyOf":[{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","minLength":1,"pattern":"\\S"},"advisory_schema_version":{"const":2,"type":"integer"}}},{"type":"null"}]},"generated_at":{"$ref":"#/$defs/timestamp"},"evaluated_at":{"$ref":"#/$defs/timestamp"},"source":{"type":"object","additionalProperties":false,"required":["id","retrieval_url","catalogue_url","configured","enabled","availability","latest_attempt","checked_at"],"properties":{"id":{"const":"cisa-kev"},"retrieval_url":{"const":"https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"},"catalogue_url":{"const":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},"configured":{"type":["boolean","null"]},"enabled":{"type":["boolean","null"]},"availability":{"enum":["available","not_configured","disabled","missing","failed","stale","future"]},"latest_attempt":{"anyOf":[{"type":"object","additionalProperties":false,"required":["checked_at","outcome","error_code"],"properties":{"checked_at":{"$ref":"#/$defs/timestamp"},"outcome":{"enum":["ok","error"]},"error_code":{"type":["string","null"]}}},{"type":"null"}]},"checked_at":{"anyOf":[{"$ref":"#/$defs/timestamp"},{"type":"null"}]}}},"catalogue":{"anyOf":[{"type":"object","additionalProperties":false,"required":["version","released_at","count","sha256","revision_id","source_observed_at","parsed_at","parser_version"],"properties":{"version":{"type":"string","minLength":1,"pattern":"\\S"},"released_at":{"$ref":"#/$defs/timestamp"},"count":{"type":"integer","minimum":1,"maximum":20000},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"revision_id":{"type":"string","minLength":1,"pattern":"\\S"},"source_observed_at":{"$ref":"#/$defs/timestamp"},"parsed_at":{"$ref":"#/$defs/timestamp"},"parser_version":{"type":"integer","const":1}}},{"type":"null"}]},"policy":{"type":"object","additionalProperties":false,"required":["max_bytes","max_entries","fresh_for_seconds","future_tolerance_seconds"],"properties":{"max_bytes":{"type":"integer","const":8000000},"max_entries":{"type":"integer","const":20000},"fresh_for_seconds":{"type":"integer","const":129600},"future_tolerance_seconds":{"type":"integer","const":300}}},"listed_cve_ids":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/cve"},"maxItems":20000},"entries":{"type":"object","propertyNames":{"$ref":"#/$defs/cve"},"additionalProperties":{"$ref":"#/$defs/entry"},"maxProperties":20000},"selection":{"type":"object","additionalProperties":false,"required":["requested_cve_ids","effective_cve_ids","kev_only","membership"],"properties":{"requested_cve_ids":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/cve"}},"effective_cve_ids":{"type":"array","uniqueItems":true,"items":{"$ref":"#/$defs/cve"}},"kev_only":{"type":"boolean"},"membership":{"type":"object","propertyNames":{"$ref":"#/$defs/cve"},"additionalProperties":{"enum":["listed","not_listed","unknown"]}}}}},"$schema":"https://json-schema.org/draft/2020-12/schema","title":"Generation-bound CISA KEV membership report v1","$defs":{"timestamp":{"type":"string","format":"date-time"},"cve":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$","not":{"pattern":"[^A-Z0-9-]"}},"entry":{"type":"object","additionalProperties":false,"required":["cveID","vendorProject","product","vulnerabilityName","shortDescription","requiredAction","dateAdded","dueDate","knownRansomwareCampaignUse","forensicTriage","notes","cwes"],"properties":{"cveID":{"$ref":"#/$defs/cve"},"vendorProject":{"type":"string","minLength":1,"pattern":"\\S"},"product":{"type":"string","minLength":1,"pattern":"\\S"},"vulnerabilityName":{"type":"string","minLength":1,"pattern":"\\S"},"shortDescription":{"type":"string","minLength":1,"pattern":"\\S"},"requiredAction":{"type":"string","minLength":1,"pattern":"\\S"},"dateAdded":{"type":"string","format":"date"},"dueDate":{"type":"string","format":"date"},"knownRansomwareCampaignUse":{"type":["string","null"]},"forensicTriage":{"type":["string","null"]},"notes":{"type":["string","null"]},"cwes":{"type":"array","items":{"type":"string"}}}}},"allOf":[{"if":{"properties":{"source":{"properties":{"configured":{"type":"null"}}}}},"then":{"properties":{"source":{"properties":{"enabled":{"type":"null"},"availability":{"const":"missing"},"checked_at":{"type":"null"},"latest_attempt":{"type":"null"}}},"catalogue":{"type":"null"}}},"else":{"properties":{"source":{"properties":{"enabled":{"type":"boolean"}}}}}},{"if":{"properties":{"catalogue":{"type":"null"}}},"then":{"properties":{"listed_cve_ids":{"maxItems":0},"entries":{"maxProperties":0}}}}]},"static-index-v1.json":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["schema_version","publication","generated_at","bootstrap","cohorts","changes","full"],"properties":{"schema_version":{"const":1},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"bootstrap":{"$ref":"#/$defs/part"},"cohorts":{"type":"object","propertyNames":{"pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"},"additionalProperties":{"type":"array","items":{"$ref":"#/$defs/part"}}},"changes":{"type":"array","items":{"$ref":"#/$defs/part"}},"full":{"type":"object","additionalProperties":false,"required":["path","sha256","bytes"],"properties":{"path":{"const":"snapshot.json"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1}}},"switching":{"type":"object","additionalProperties":false,"required":["inputs","kev_entries","evidence_metadata","has_score_availability"],"properties":{"summary":{"$ref":"#/$defs/part"},"inputs":{"$ref":"#/$defs/part"},"claims":{"$ref":"#/$defs/claim_entries"},"kev_entries":{"type":"array","items":{"$ref":"#/$defs/part"}},"evidence_metadata":{"type":"array","items":{"$ref":"#/$defs/part"}},"has_score_availability":{"type":"boolean"},"summary_fragments":{"type":"object","additionalProperties":false,"required":["parts","sha256","bytes"],"properties":{"parts":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/part"}},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":128000000}}},"claim_catalog":{"type":"array","minItems":1,"items":{"$ref":"#/$defs/part"}}},"oneOf":[{"required":["summary"]},{"required":["summary_fragments"]}],"allOf":[{"oneOf":[{"required":["claims"]},{"required":["claim_catalog"]}]}]},"current_evidence":{"type":"object","additionalProperties":false,"required":["schema_version","report","retained"],"properties":{"schema_version":{"const":1},"report":{"$ref":"#/$defs/part"},"retained":{"type":"array","maxItems":1000,"items":{"type":"object","additionalProperties":false,"required":["decision_ids","cve_ids","part"],"properties":{"decision_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"cve_ids":{"type":"array","uniqueItems":true,"items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"}},"part":{"$ref":"#/$defs/part"}}}}}}},"$defs":{"part":{"type":"object","additionalProperties":false,"required":["path","sha256","bytes"],"properties":{"path":{"type":"string","pattern":"^data/[a-f0-9]{64}\\.json$"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":8000000}}},"claim_entry":{"type":"object","additionalProperties":false,"required":["claim_ids","part"],"properties":{"claim_ids":{"type":"array","uniqueItems":true,"items":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"part":{"$ref":"#/$defs/part"}}},"claim_entries":{"type":"array","items":{"$ref":"#/$defs/claim_entry"}}}},"static-index-v2.json":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["schema_version","publication","generated_at","bootstrap","cohorts","changes","publication_v2"],"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"bootstrap":{"$ref":"#/$defs/part"},"cohorts":{"type":"object","propertyNames":{"pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"},"additionalProperties":{"type":"array","items":{"$ref":"#/$defs/part"}}},"changes":{"type":"array","items":{"$ref":"#/$defs/part"}},"current_evidence":{"type":"object","additionalProperties":false,"required":["schema_version","report","retained"],"properties":{"schema_version":{"const":1},"report":{"$ref":"#/$defs/part"},"retained":{"type":"array","maxItems":1000,"items":{"type":"object","additionalProperties":false,"required":["decision_ids","cve_ids","part"],"properties":{"decision_ids":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"cve_ids":{"type":"array","uniqueItems":true,"items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,}$"}},"part":{"$ref":"#/$defs/part"}}}}}},"publication_v2":{"type":"object","additionalProperties":false,"properties":{"path":{"const":"publication-v2.json"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":2000000}},"required":["path","sha256","bytes"]}},"$defs":{"part":{"type":"object","additionalProperties":false,"required":["path","sha256","bytes"],"properties":{"path":{"type":"string","pattern":"^data/[a-f0-9]{64}\\.json$"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":8000000}}},"claim_entry":{"type":"object","additionalProperties":false,"required":["claim_ids","part"],"properties":{"claim_ids":{"type":"array","uniqueItems":true,"items":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"part":{"$ref":"#/$defs/part"}}},"claim_entries":{"type":"array","items":{"$ref":"#/$defs/claim_entry"}}},"$id":"urn:infrastructure-impact:static-index:2"},"publication-v2.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"representation":{"const":"publication-catalog"},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"codec":{"const":"json-token-v1"},"strings":{"type":"array","items":{"$ref":"#/$defs/table"}},"shapes":{"type":"array","items":{"$ref":"#/$defs/table"}},"roots":{"type":"object","propertyNames":{"type":"string","pattern":"^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(?:\\.json)?$"},"additionalProperties":{"$ref":"#/$defs/part"},"required":["snapshot.json","runtime-snapshot","switching-evidence.json","switching-comparison.json"]},"routes":{"type":"object","additionalProperties":false,"properties":{"claims":{"type":"array","items":{"$ref":"#/$defs/part"}},"records":{"type":"array","items":{"$ref":"#/$defs/part"}}},"required":["claims","records"]},"switching":{"type":"object","additionalProperties":false,"properties":{"overview":{"$ref":"#/$defs/part"},"definition_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"kev":{"$ref":"#/$defs/range"},"diagnostics":{"$ref":"#/$defs/range"},"detail_indexes":{"type":"object","additionalProperties":false,"properties":{"sources":{"type":"array","items":{"$ref":"#/$defs/detail_chunk"}},"diagnostics":{"type":"array","items":{"$ref":"#/$defs/detail_chunk"}}},"required":["sources","diagnostics"]}},"required":["overview","definition_sha256","kev","diagnostics"]},"archive":{"type":"object","additionalProperties":false,"properties":{"scope":{"const":"snapshot-v1"},"manifest":{"$ref":"#/$defs/part"},"expanded":{"type":"object","additionalProperties":false,"properties":{"path":{"const":"snapshot-v2.json"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":128000000}},"required":["path","sha256","bytes"]},"gzip":{"type":"object","additionalProperties":false,"properties":{"path":{"const":"snapshot-v2.json.gz"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":8000000}},"required":["path","sha256","bytes"]}},"required":["scope","manifest","expanded","gzip"]}},"required":["schema_version","representation","publication","generated_at","codec","strings","shapes","roots","routes","switching","archive"],"$defs":{"part":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string","pattern":"^data/v2/[a-f0-9]{64}\\.json$"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":8000000}},"required":["path","sha256","bytes"]},"range":{"type":"object","additionalProperties":false,"properties":{"root":{"type":"string","pattern":"^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(?:\\.json)?$"},"first_token":{"type":"integer","minimum":0,"maximum":9007199254740991},"end_token":{"type":"integer","minimum":1,"maximum":9007199254740991},"logical_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"logical_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"required":["root","first_token","end_token","logical_bytes","logical_sha256"]},"logical":{"type":"object","additionalProperties":false,"properties":{"bytes":{"type":"integer","minimum":1,"maximum":9007199254740991},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}},"required":["bytes","sha256"]},"table":{"type":"object","additionalProperties":false,"properties":{"part":{"$ref":"#/$defs/part"},"first":{"type":"integer","minimum":0,"maximum":9007199254740991},"count":{"type":"integer","minimum":1,"maximum":9007199254740991}},"required":["part","first","count"]},"path":{"type":"array","items":{"oneOf":[{"type":"string"},{"type":"integer","minimum":0,"maximum":9007199254740991}]}},"page":{"type":"object","additionalProperties":false,"properties":{"part":{"$ref":"#/$defs/part"},"first_token":{"type":"integer","minimum":0,"maximum":9007199254740991},"count":{"type":"integer","minimum":1,"maximum":9007199254740991},"decoded_upper_bound":{"type":"integer","minimum":1,"maximum":9007199254740991}},"required":["part","first_token","count","decoded_upper_bound"]},"root":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string","pattern":"^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+(?:\\.json)?$"},"token_count":{"type":"integer","minimum":1,"maximum":9007199254740991},"logical":{"$ref":"#/$defs/logical"},"pages":{"type":"array","items":{"$ref":"#/$defs/page"},"minItems":1},"ranges":{"type":"array","items":{"$ref":"#/$defs/part"}}},"required":["name","token_count","logical","pages","ranges"]},"claim_routes":{"type":"object","additionalProperties":false,"properties":{"base":{"type":"integer","minimum":0,"maximum":9007199254740991},"final_end":{"type":"integer","minimum":1,"maximum":9007199254740991},"rows":{"type":"array","items":{"type":"array","prefixItems":[{"type":"integer","minimum":0,"maximum":9007199254740991},{"type":"integer","minimum":0,"maximum":9007199254740991},{"type":"integer","minimum":1,"maximum":9007199254740991}],"items":false,"minItems":3,"maxItems":3},"minItems":1}},"required":["base","final_end","rows"]},"record_routes":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"record_index":{"type":"integer","minimum":0,"maximum":9007199254740991},"first_token":{"type":"integer","minimum":0,"maximum":9007199254740991},"end_token":{"type":"integer","minimum":1,"maximum":9007199254740991},"logical_bytes":{"type":"integer","minimum":1,"maximum":9007199254740991}},"required":["record_index","first_token","end_token","logical_bytes"]}},"ranges":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"path":{"$ref":"#/$defs/path"},"range":{"$ref":"#/$defs/range"}},"required":["path","range"]}},"strings":{"type":"array","items":{"type":"string"},"minItems":1},"shapes":{"type":"array","items":{"type":"array","items":{"type":"string"},"uniqueItems":true},"minItems":1,"uniqueItems":true},"token":{"oneOf":[{"type":"null"},{"type":"boolean"},{"type":"integer","minimum":-9007199254740991,"maximum":-2},{"type":"array","prefixItems":[{"type":"integer","minimum":0,"maximum":9007199254740991}],"items":false,"minItems":1,"maxItems":1},{"type":"array","prefixItems":[{"const":-1},{"type":"integer","minimum":0,"maximum":9007199254740991}],"items":false,"minItems":2,"maxItems":2},{"type":"array","prefixItems":[{"const":-2},{"enum":["i","f"]},{"type":"string","pattern":"^-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$"}],"items":false,"minItems":3,"maxItems":3},{"type":"array","prefixItems":[{"const":-3},{"const":"switching-evidence.json"}],"items":false,"minItems":2,"maxItems":2}]},"tokens":{"type":"array","items":{"$ref":"#/$defs/token"},"minItems":1},"archive_scope":{"type":"object","additionalProperties":false,"properties":{"scope":{"const":"snapshot-v1"},"root":{"$ref":"#/$defs/part"},"strings":{"type":"array","items":{"$ref":"#/$defs/table"}},"shapes":{"type":"array","items":{"$ref":"#/$defs/table"}},"record_routes":{"type":"array","items":{"$ref":"#/$defs/part"}},"members":{"type":"array","items":{"$ref":"#/$defs/part"},"minItems":1},"legacy_snapshot":{"$ref":"#/$defs/logical"}},"required":["scope","root","strings","shapes","record_routes","members","legacy_snapshot"]},"envelope":{"oneOf":[{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"strings"},"data":{"$ref":"#/$defs/strings"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"shapes"},"data":{"$ref":"#/$defs/shapes"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"tokens"},"data":{"$ref":"#/$defs/tokens"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"root"},"data":{"$ref":"#/$defs/root"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"claim_routes"},"data":{"$ref":"#/$defs/claim_routes"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"record_routes"},"data":{"$ref":"#/$defs/record_routes"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"ranges"},"data":{"$ref":"#/$defs/ranges"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"overview"},"data":{"$ref":"urn:infrastructure-impact:switching-overview:2"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"archive"},"data":{"$ref":"#/$defs/archive_scope"}},"required":["schema_version","publication","generated_at","kind","data"]},{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"kind":{"const":"detail_index"},"data":{"$ref":"#/$defs/detail_index"}},"required":["schema_version","publication","generated_at","kind","data"]}]},"archive":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"representation":{"const":"snapshot-archive"},"publication":{"type":"object","additionalProperties":false,"required":["id","advisory_schema_version"],"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"const":2}}},"generated_at":{"type":"string","format":"date-time"},"assets":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string","pattern":"^data/v2/[a-f0-9]{64}\\.json$"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"bytes":{"type":"integer","minimum":1,"maximum":8000000},"data":{"$ref":"#/$defs/envelope"}},"required":["path","sha256","bytes","data"]},"minItems":1}},"required":["schema_version","representation","publication","generated_at","assets"]},"detail_index":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"ordinal":{"type":"integer","minimum":0,"maximum":9007199254740991},"vendor":{"type":"string"},"range":{"$ref":"#/$defs/range"}},"required":["ordinal","range"]},"minItems":1},"detail_chunk":{"type":"object","additionalProperties":false,"properties":{"first":{"type":"integer","minimum":0,"maximum":9007199254740991},"count":{"type":"integer","minimum":1,"maximum":9007199254740991},"vendors":{"type":"object","additionalProperties":{"type":"integer","minimum":1,"maximum":9007199254740991}},"part":{"$ref":"#/$defs/part"}},"required":["first","count","vendors","part"]}},"$id":"urn:infrastructure-impact:publication:2","$schema":"https://json-schema.org/draft/2020-12/schema"},"switching-overview-v2.json":{"type":"object","additionalProperties":false,"properties":{"schema_version":{"const":2},"publication":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/publication"},"generated_at":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/generated_at"},"evaluated_at":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/evaluated_at"},"definition":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/definition"},"selection":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/selection"},"rows":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"row_id":{"type":"string","minLength":1},"vendor":{"enum":["cisco","aruba","arista"]},"scope_level":{"enum":["os_family","model_qualified"]},"window":{"type":"string","pattern":"^(all|pre|post|undated|[0-9]{4})$"},"period_start":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"period_end":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},"date_basis":{"const":"initial_publisher_date_utc_day"},"event_date_basis":{"const":"explicit_bundle_initial_else_advisory_initial"},"affected_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"counts":{"type":"object","additionalProperties":false,"properties":{"advisories":{"type":"integer","minimum":0},"cves":{"type":"integer","minimum":0},"claims":{"type":"integer","minimum":0},"affected_cves":{"type":"integer","minimum":0},"conditional_cves":{"type":"integer","minimum":0},"draft_advisories":{"type":"integer","minimum":0},"remediation_events":{"type":"integer","minimum":0},"bundled_events":{"type":"integer","minimum":0},"unbundled_publications":{"type":"integer","minimum":0},"fixed_only_claims":{"type":"integer","minimum":0},"planned_fix_claims":{"type":"integer","minimum":0},"workaround_claims":{"type":"integer","minimum":0},"model_unresolved_claims":{"type":"integer","minimum":0},"conditionality_unclassified_cves":{"type":"integer","minimum":0},"affected_advisories":{"type":"integer","minimum":0}},"required":["advisories","cves","claims","affected_cves","conditional_cves","draft_advisories","remediation_events","bundled_events","unbundled_publications","fixed_only_claims","planned_fix_claims","workaround_claims","model_unresolved_claims","conditionality_unclassified_cves","affected_advisories"]},"status_buckets":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"status":{"enum":["affected","unaffected","fixed","investigating","unknown","partially_mitigated","recommended","conflicting"]},"scope":{"enum":["cve_specific","bulletin_shared","unresolved"]},"claim_ids":{"type":"array","items":{"type":"string","pattern":"^[a-f0-9]{64}$"},"uniqueItems":true},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["status","scope","claim_ids","cve_ids","count"]},"uniqueItems":true},"severity":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"version":{"anyOf":[{"enum":["2.0","3.0","3.1","4.0"]},{"type":"null"}]},"provider":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"origin":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"preferred":{"anyOf":[{"type":"boolean"},{"type":"null"}]},"band":{"enum":["None","Low","Medium","High","Critical","Unknown"]},"cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["version","provider","origin","preferred","band","cve_ids","count"]},"uniqueItems":true},"vendor_severity":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"rating":{"type":"string","minLength":1},"scheme":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"namespace":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},"scope":{"const":"advisory"},"advisory_ids":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"count":{"type":"integer","minimum":0}},"required":["rating","scheme","namespace","scope","advisory_ids","count"]},"uniqueItems":true},"kev":{"type":"object","additionalProperties":false,"properties":{"availability":{"enum":["available","missing","disabled","failed","stale","future","not_configured"]},"listed_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"unknown_cve_ids":{"type":"array","items":{"type":"string","pattern":"^CVE-[0-9]{4}-[0-9]{4,19}$"},"uniqueItems":true},"listed_count":{"type":"integer","minimum":0},"unknown_count":{"type":"integer","minimum":0},"denominator":{"type":"integer","minimum":0}},"required":["availability","listed_cve_ids","unknown_cve_ids","listed_count","unknown_count","denominator"]},"coverage":{"type":"object","additionalProperties":false,"properties":{"state":{"enum":["partial","unknown"]},"expected_advisories":{"type":"null"},"observed_advisories":{"type":"integer","minimum":0},"basis":{"const":"retained_source_windows_not_period_completeness"},"sources":{"type":"array","items":{"$ref":"urn:infrastructure-impact:switching-evidence:1#/$defs/coverage"},"uniqueItems":true}},"required":["state","expected_advisories","observed_advisories","basis","sources"]},"denominators":{"type":"object","additionalProperties":false,"properties":{"affected_cves":{"type":"integer","minimum":0},"observed_advisories":{"type":"integer","minimum":0},"expected_advisories":{"type":"null"}},"required":["affected_cves","observed_advisories","expected_advisories"]},"issues":{"type":"array","items":{"type":"string","minLength":1},"uniqueItems":true},"detail_ranges":{"type":"object","additionalProperties":false,"properties":{"advisory_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"affected_advisory_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"cve_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"claim_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"conditional_cve_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"event_ids":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"},"events":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"}},"required":["advisory_ids","affected_advisory_ids","cve_ids","claim_ids","conditional_cve_ids","event_ids","events"]}},"required":["row_id","vendor","scope_level","window","period_start","period_end","date_basis","event_date_basis","affected_cve_ids","counts","status_buckets","severity","vendor_severity","kev","coverage","denominators","issues","detail_ranges"]},"uniqueItems":true},"issues":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/issues"},"method":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/method"},"availability":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/availability"},"observation_end":{"$ref":"urn:infrastructure-impact:switching-comparison:1#/properties/observation_end"},"representation":{"const":"switching-overview"},"detail_ranges":{"type":"object","additionalProperties":false,"properties":{"sources":{"$ref":"urn:infrastructure-impact:publication:2#/$defs/range"}},"required":["sources"]}},"required":["schema_version","publication","generated_at","evaluated_at","definition","selection","rows","issues","method","availability","observation_end","representation","detail_ranges"],"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:infrastructure-impact:switching-overview:2","title":"Explicit bounded switching overview v2"},"current-evidence-v1.json":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["schema_version","availability","publication","generated_at","policies","decisions","issues","counts"],"properties":{"schema_version":{"const":1},"availability":{"enum":["available","unavailable"]},"publication":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"advisory_schema_version":{"type":"integer","const":2}},"required":["id","advisory_schema_version"]},{"type":"null"}]},"generated_at":{"type":"string","format":"date-time"},"policies":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["vendor","policy_id","version","fingerprint","reason_text"],"properties":{"vendor":{"type":"string","minLength":1,"maxLength":128},"policy_id":{"type":"string","minLength":1,"maxLength":128},"version":{"type":"string","minLength":1,"maxLength":128},"fingerprint":{"type":"string","pattern":"^[a-f0-9]{64}$"},"reason_text":{"type":"string","minLength":1,"maxLength":500}}},"maxItems":1000,"minItems":0},"decisions":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["decision_id","vendor","policy_id","policy_version","policy_fingerprint","target_key","disposition","reason","reason_text","proofs","target"],"properties":{"decision_id":{"type":"string","pattern":"^[a-f0-9]{64}$"},"vendor":{"type":"string","minLength":1,"maxLength":128},"policy_id":{"type":"string","minLength":1,"maxLength":128},"policy_version":{"type":"string","minLength":1,"maxLength":128},"policy_fingerprint":{"type":"string","pattern":"^[a-f0-9]{64}$"},"target_key":{"type":"string","pattern":"^[a-f0-9]{64}$"},"disposition":{"const":"excluded_from_current"},"reason":{"const":"reviewed_representation_scope_conflict"},"reason_text":{"type":"string","minLength":1,"maxLength":500},"proofs":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["source_url","source_sha256","evidence_id","source_observed_at","locator"],"properties":{"source_url":{"type":"string","format":"uri","pattern":"^https://","maxLength":2048},"source_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"evidence_id":{"type":"integer","minimum":1},"source_observed_at":{"type":"string","format":"date-time"},"locator":{"type":"string","minLength":1,"maxLength":256}}},"maxItems":20,"minItems":1},"target":{"type":"object","additionalProperties":false,"required":["vendor","advisory_id","revision_id","source_url","sha256"],"properties":{"vendor":{"type":"string","minLength":1},"advisory_id":{"type":"string","minLength":1},"source_url":{"type":"string","minLength":1},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"},"revision_id":{"oneOf":[{"type":"integer","minimum":1},{"type":"string","minLength":1,"maxLength":128}]}}}}},"maxItems":1000,"minItems":0},"issues":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["vendor","policy_id","target_key","code"],"properties":{"vendor":{"type":"string","minLength":1,"maxLength":128},"policy_id":{"type":"string","minLength":1,"maxLength":128},"target_key":{"type":"string","pattern":"^[a-f0-9]{64}$"},"code":{"const":"proof_unresolved"}}},"maxItems":1000,"minItems":0},"counts":{"type":"object","additionalProperties":false,"required":["current","retained_total","excluded"],"properties":{"current":{"type":["integer","null"],"minimum":0},"retained_total":{"type":["integer","null"],"minimum":0},"excluded":{"type":["integer","null"],"minimum":0}}}},"allOf":[{"if":{"properties":{"availability":{"const":"available"}}},"then":{"properties":{"counts":{"type":"object","additionalProperties":false,"required":["current","retained_total","excluded"],"properties":{"current":{"type":"integer","minimum":0},"retained_total":{"type":"integer","minimum":0},"excluded":{"type":"integer","minimum":0}}}}},"else":{"properties":{"counts":{"type":"object","additionalProperties":false,"required":["current","retained_total","excluded"],"properties":{"current":{"type":"null"},"retained_total":{"type":"null"},"excluded":{"type":"null"}}},"policies":{"maxItems":0},"decisions":{"maxItems":0},"issues":{"maxItems":0}}}}]}},"definition_sha256":"5224471b014fccc278f985d08328926bac29ebc6bfb96d25f98972f91be6fd33"}; /* END GENERATED CONTRACTS */
  const schemas = bundle.schemas;
  const roots = Object.fromEntries(
    Object.entries(schemas).map(([name, schema]) => [
      schema.$id || (name === 'kev-v1.json' ? 'urn:infrastructure-impact:kev:1' : name),
      schema,
    ]),
  );
  const compareText = (a, b) => {
    const left = Array.from(a),
      right = Array.from(b);
    for (let i = 0; i < Math.min(left.length, right.length); i++) {
      const delta = left[i].codePointAt(0) - right[i].codePointAt(0);
      if (delta) return delta;
    }
    return left.length - right.length;
  };
  const canonical = (value) =>
    (window.InfrastructureJSON?.stringify ?? JSON.stringify)(value, (_, v) =>
      v && typeof v === 'object' && !Array.isArray(v)
        ? Object.fromEntries(
            Object.keys(v)
              .sort(compareText)
              .map((k) => [k, v[k]]),
          )
        : v,
    );
  const equal = (a, b) => canonical(a) === canonical(b);
  const fail = (message) => {
    throw Error('Invalid switching contract: ' + message);
  };
  function sha256(text) {
    // Synchronous SHA-256 keeps pure selection synchronous; URI encoding rejects lone surrogates.
    const bytes = Array.from(encodeURIComponent(text).matchAll(/%([0-9A-F]{2})|([^%])/g), (m) =>
      m[1] ? parseInt(m[1], 16) : m[2].charCodeAt(0),
    );
    const length = bytes.length,
      words = [];
    bytes.push(128);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let i = 7; i >= 0; i--) bytes.push(Math.floor((length * 8) / 2 ** (i * 8)) & 255);
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2,
    ];
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
      0x5be0cd19,
    ];
    const rotate = (v, n) => (v >>> n) | (v << (32 - n));
    for (let offset = 0; offset < bytes.length; offset += 64) {
      for (let i = 0; i < 16; i++)
        words[i] =
          (bytes[offset + i * 4] << 24) |
          (bytes[offset + i * 4 + 1] << 16) |
          (bytes[offset + i * 4 + 2] << 8) |
          bytes[offset + i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const a = words[i - 15],
          b = words[i - 2];
        words[i] =
          (words[i - 16] +
            (rotate(a, 7) ^ rotate(a, 18) ^ (a >>> 3)) +
            words[i - 7] +
            (rotate(b, 17) ^ rotate(b, 19) ^ (b >>> 10))) |
          0;
      }
      let [a, b, c, d, e, f, g, h] = hash;
      for (let i = 0; i < 64; i++) {
        const t1 =
          (h +
            (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
            ((e & f) ^ (~e & g)) +
            constants[i] +
            words[i]) |
          0;
        const t2 =
          ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        [a, b, c, d, e, f, g, h] = [(t1 + t2) | 0, a, b, c, (d + t1) | 0, e, f, g];
      }
      [a, b, c, d, e, f, g, h].forEach((v, i) => {
        hash[i] = (hash[i] + v) | 0;
      });
    }
    return hash.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
  }
  // Exact finite binary64 decimal tokens match Decimal.from_float in Python;
  // source values stay untouched. No shortest-string or exponent convention is
  // assumed. Integral values (including -0) use ordinary JSON integer tokens.
  function numberToken(value) {
    if (!Number.isFinite(value)) fail('nonfinite fingerprint number');
    if (Number.isInteger(value)) return String(value);
    const buffer = new ArrayBuffer(8),
      view = new DataView(buffer);
    view.setFloat64(0, value);
    const bits = view.getBigUint64(0),
      negative = bits >> 63n;
    const exponent = Number((bits >> 52n) & 2047n);
    const mantissa = (bits & ((1n << 52n) - 1n)) | (exponent ? 1n << 52n : 0n);
    const power = (exponent || 1) - 1023 - 52;
    let token;
    if (power >= 0) token = (mantissa << BigInt(power)).toString();
    else {
      const places = -power;
      const digits = (mantissa * 5n ** BigInt(places)).toString().padStart(places + 1, '0');
      token = (digits.slice(0, -places) + '.' + digits.slice(-places)).replace(/0+$/, '');
    }
    return (negative ? '-' : '') + token;
  }
  function fingerprintJSON(value) {
    if (typeof value === 'number') return numberToken(value);
    if (Array.isArray(value)) return '[' + value.map(fingerprintJSON).join(',') + ']';
    if (value && typeof value === 'object')
      return (
        '{' +
        Object.keys(value)
          .sort(compareText)
          .map((k) => JSON.stringify(k) + ':' + fingerprintJSON(value[k]))
          .join(',') +
        '}'
      );
    return JSON.stringify(value);
  }
  const fingerprint = (value) => sha256(fingerprintJSON(value));
  const supported = new Set([
    '$schema',
    '$id',
    '$defs',
    '$ref',
    'title',
    'description',
    'type',
    'properties',
    'additionalProperties',
    'required',
    'propertyNames',
    'maxProperties',
    'items',
    'prefixItems',
    'minItems',
    'maxItems',
    'uniqueItems',
    'minimum',
    'maximum',
    'minLength',
    'maxLength',
    'pattern',
    'format',
    'enum',
    'const',
    'anyOf',
    'oneOf',
    'allOf',
    'not',
    'if',
    'then',
    'else',
  ]);
  function checkSchema(s) {
    if (typeof s === 'boolean') return;
    for (const key of Object.keys(s))
      if (!supported.has(key)) fail('unsupported schema keyword ' + key);
    for (const key of ['properties', '$defs']) Object.values(s[key] || {}).forEach(checkSchema);
    for (const key of [
      'additionalProperties',
      'propertyNames',
      'items',
      'not',
      'if',
      'then',
      'else',
    ])
      if (s[key] !== undefined) checkSchema(s[key]);
    for (const key of ['allOf', 'anyOf', 'oneOf', 'prefixItems'])
      (s[key] || []).forEach(checkSchema);
  }
  Object.values(schemas).forEach(checkSchema);
  function resolve(ref, root) {
    const [base, fragment = ''] = ref.split('#');
    const next = base ? roots[base] : root;
    if (!next || (fragment && !fragment.startsWith('/'))) fail('unregistered schema reference');
    let shape = next;
    if (fragment)
      for (const key of fragment.slice(1).split('/'))
        shape = shape?.[key.replaceAll('~1', '/').replaceAll('~0', '~')];
    if (shape === undefined) fail('missing schema reference');
    return [shape, next];
  }
  function validDay(value) {
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
    if (!match) return false;
    const [y, m, d] = match.slice(1).map(Number),
      leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
    return (
      y >= 1 &&
      m >= 1 &&
      m <= 12 &&
      d >= 1 &&
      d <= [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]
    );
  }
  function format(value, kind) {
    if (kind === 'date') return validDay(value);
    if (kind === 'date-time') {
      const match =
        /^(\d{4}-\d{2}-\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/.exec(
          value,
        );
      return (
        !!match &&
        validDay(match[1]) &&
        +match[2] < 24 &&
        +match[3] < 60 &&
        +match[4] < 60 &&
        +(match[6] || 0) < 24 &&
        +(match[7] || 0) < 60
      );
    }
    if (kind === 'uri')
      return (
        /^https:\/\/[^/?#\s]+(?:[/?#]|$)/.test(value) &&
        /^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*$/.test(value) &&
        !/%(?![0-9a-fA-F]{2})/.test(value) &&
        !/[\[\]]/.test(value.replace(/^https:\/\/[^/?#]+/, ''))
      );
    fail('unsupported format');
  }
  function matches(value, s, root) {
    try {
      check(value, s, root);
      return true;
    } catch {
      return false;
    }
  }
  function check(value, s, root) {
    if (s === true) return;
    if (s === false) fail('forbidden value');
    if (s.$ref) {
      const [shape, next] = resolve(s.$ref, root);
      check(value, shape, next);
    }
    if (s.type) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      if (
        !types.some((t) =>
          t === 'null'
            ? value === null
            : t === 'object'
              ? value !== null && typeof value === 'object' && !Array.isArray(value)
              : t === 'array'
                ? Array.isArray(value)
                : t === 'integer'
                  ? typeof value === 'bigint' ||
                    (typeof value === 'number' && Number.isSafeInteger(value))
                  : t === 'number'
                    ? typeof value === 'number' && Number.isFinite(value)
                    : typeof value === t,
        )
      )
        fail('type');
    }
    if (Object.hasOwn(s, 'const') && !equal(value, s.const)) fail('constant');
    if (s.enum && !s.enum.some((v) => equal(value, v))) fail('enum');
    if (s.oneOf && s.oneOf.filter((shape) => matches(value, shape, root)).length !== 1)
      fail('oneOf');
    if (s.anyOf && !s.anyOf.some((shape) => matches(value, shape, root))) fail('anyOf');
    for (const shape of s.allOf || []) check(value, shape, root);
    if (s.not && matches(value, s.not, root)) fail('not');
    if (s.if) {
      const branch = matches(value, s.if, root) ? s.then : s.else;
      if (branch) check(value, branch, root);
    }
    if (
      (typeof value === 'number' || typeof value === 'bigint') &&
      ((typeof value === 'number' && !Number.isFinite(value)) ||
        (s.minimum !== undefined && value < s.minimum) ||
        (s.maximum !== undefined && value > s.maximum))
    )
      fail('number bounds');
    if (typeof value === 'string') {
      const length = Array.from(value).length;
      if (
        (s.minLength !== undefined && length < s.minLength) ||
        (s.maxLength !== undefined && length > s.maxLength) ||
        (s.pattern && !new RegExp(s.pattern).test(value)) ||
        (s.format && !format(value, s.format))
      )
        fail('string constraint');
    }
    if (Array.isArray(value)) {
      if (
        (s.minItems !== undefined && value.length < s.minItems) ||
        (s.maxItems !== undefined && value.length > s.maxItems) ||
        (s.uniqueItems && new Set(value.map(canonical)).size !== value.length)
      )
        fail('array bounds/uniqueness');
      for (let i = 0; i < value.length; i++) {
        if (i < (s.prefixItems?.length || 0)) check(value[i], s.prefixItems[i], root);
        else if (s.items !== undefined) check(value[i], s.items, root);
      }
    } else if (value !== null && typeof value === 'object') {
      const keys = Object.keys(value);
      if (
        (s.maxProperties !== undefined && keys.length > s.maxProperties) ||
        (s.required || []).some((k) => !Object.hasOwn(value, k))
      )
        fail('object fields');
      for (const key of keys) {
        if (s.propertyNames) check(key, s.propertyNames, root);
        if (Object.hasOwn(s.properties || {}, key)) check(value[key], s.properties[key], root);
        else if (s.additionalProperties !== undefined)
          check(value[key], s.additionalProperties, root);
      }
    }
  }
  function validate(name, value, fragment = '') {
    const root = schemas[name];
    if (!root) fail('unknown schema');
    const [shape] = resolve('#' + fragment, root);
    check(value, shape, root);
    return value;
  }
  function identity(value, enclosing) {
    if (
      !equal(value.publication, enclosing.publication) ||
      value.generated_at !== enclosing.generated_at
    )
      fail('mixed generations');
  }
  function definition(report) {
    const hash = fingerprint(report.definition);
    if (hash !== report.selection.definition_sha256 || hash !== bundle.definition_sha256)
      fail('definition fingerprint');
    return hash;
  }
  function summary(report, enclosing = report) {
    validate('switching-summary-v1.json', report);
    identity(report, enclosing);
    definition(report);
    return report;
  }
  function header(value, enclosing, definitionHash) {
    validate('switching-inputs-v1.json', value);
    for (const input of [value.evidence, value.kev]) identity(input, enclosing);
    if (
      value.evidence.definition_sha256 !== definitionHash ||
      definitionHash !== bundle.definition_sha256
    )
      fail('input definition fingerprint');
    return value;
  }
  function reviewedSections(claims) {
    for (const c of claims)
      for (const r of c.remediations) {
        const b = r.scope_binding;
        if (!b || b.basis !== 'reviewed_source_sections') continue;
        const matching = claims.filter(
          (f) =>
            f.vendor === 'arista' &&
            f.advisory_id === c.advisory_id &&
            f.revision === c.revision &&
            equal(f.publisher, c.publisher) &&
            f.status === 'fixed' &&
            f.scope === 'cve_specific' &&
            f.cve_id === c.cve_id &&
            f.product === b.fixed_product &&
            equal(f.source, b.fixed_source),
        );
        if (
          c.vendor !== 'arista' ||
          c.advisory_id !== '19904-security-advisory-0100' ||
          c.source.source_url !==
            'https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100' ||
          !['CVE-2024-6387', 'CVE-2024-6409'].includes(c.cve_id) ||
          b.cve_id !== c.cve_id ||
          c.status !== 'affected' ||
          c.scope !== 'cve_specific' ||
          c.product !== 'EOS release (source platform scope applies)' ||
          c.source.source_locator !==
            'Affected Software / EOS release (source platform scope applies)' ||
          r.source.source_locator !== 'Resolution / ' + c.cve_id + ' / Arista EOS-based products' ||
          !equal(b.source, c.source) ||
          !equal(b.fixed_source, r.source) ||
          matching.length !== 1 ||
          r.product_ids.length !== 0 ||
          !equal(r.version_expressions, matching[0].version_expressions) ||
          !matching[0].remediations.some((f) =>
            [
              'publisher_id',
              'category',
              'details',
              'published_availability',
              'availability',
              'availability_date',
              'source',
            ].every((k) => equal(r[k] ?? null, f[k] ?? null)),
          ) ||
          ['source_url', 'source_sha256', 'retrieved_at'].some((k) => c.source[k] !== r.source[k])
        )
          fail('reviewed section EOS/CVE linkage');
      }
  }
  function official(url, vendor, reference = false) {
    const match = /^https:\/\/([^/?#]+)([^?#]*)(.*)$/.exec(url);
    if (!match || /@/.test(match[1])) fail('public official HTTPS source');
    const host = match[1].replace(/:443$/, '').toLowerCase();
    if (host.includes(':')) fail('official source port');
    const within = (domain) => host === domain || host.endsWith('.' + domain);
    const domains = {
      cisco: ['cisco.com'],
      aruba: ['hpe.com', 'arubanetworks.com'],
      arista: ['arista.com'],
    };
    const registry =
      host === 'cveawg.mitre.org' && /^\/api\/cve\/CVE-\d{4}-\d{4,}$/.test(match[2]) && !match[3];
    if ((domains[vendor] || []).some(within) || (vendor === 'cisco' && registry)) return;
    if (!reference) fail('vendor source provenance');
    if (
      ['cve.org', 'nvd.nist.gov'].some(within) ||
      (registry && url === 'https://cveawg.mitre.org' + match[2])
    )
      return;
    fail('score reference provenance');
  }
  const missing = (issues, value, code) => {
    if (value === null && !issues.includes(code)) fail('missing evidence issue ' + code);
  };
  const sourceIdentity = (a, b) =>
    ['source_url', 'source_sha256', 'retrieved_at'].every((k) => a[k] === b[k]);
  function evidenceSemantics(evidence, study, scoped = false) {
    const seen = new Set();
    for (const c of evidence.claims) {
      const { claim_id, ...body } = c;
      if (claim_id !== fingerprint(body) || seen.has(claim_id))
        fail('deterministic unique claim IDs');
      seen.add(claim_id);
      official(c.source.source_url, c.vendor);
      for (const [key, code] of [
        ['revision', 'revision_missing'],
        ['cve_id', 'cve_id_missing'],
        ['product_id', 'product_id_missing'],
        ['product', 'product_missing'],
        ['family', 'family_unresolved'],
        ['initial_published_at', 'initial_publication_date_missing'],
        ['updated_at', 'update_date_missing'],
      ])
        missing(c.issues, c[key], code);
      for (const key of ['id', 'sequence', 'status'])
        missing(c.issues, c.publisher[key], 'publisher_' + key + '_missing');
      if (c.publisher.source) {
        official(c.publisher.source.source_url, c.vendor);
        if (!sourceIdentity(c.publisher.source, c.source)) fail('publisher source identity');
      }
      const qualified =
        c.platform_bindings.length > 0 &&
        c.platform_bindings.every((b) => b.basis !== 'unresolved') &&
        equal(
          [...new Set(c.platform_bindings.map((b) => b.platform))].sort(),
          [...c.named_platforms].sort(),
        );
      if (c.scope_level === 'model_qualified' && !qualified) fail('unresolved model qualification');
      if (!qualified && !c.issues.includes('model_binding_unresolved')) fail('model issue missing');
      for (const b of c.platform_bindings) {
        if (!c.named_platforms.includes(b.platform)) fail('named platform closure');
        if (b.basis === 'unresolved') {
          if (b.model !== null) fail('unresolved model assertion');
        } else {
          if (b.model === null || b.source === null) fail('positive model provenance');
          const targets = study.targets.filter(
            (t) => t.vendor === c.vendor && t.family === c.family && t.models.includes(b.model),
          );
          if (!targets.length) fail('registered vendor/family/model');
          if (
            b.basis === 'reviewed_alias' &&
            !targets.some((t) =>
              t.aliases.some(
                (a) =>
                  a.literal === b.platform &&
                  a.model === b.model &&
                  a.source_url === b.source.source_url &&
                  a.source_locator === b.source.source_locator,
              ),
            )
          )
            fail('registered alias locator');
        }
        if (b.source) official(b.source.source_url, c.vendor);
      }
      for (const r of c.remediations) {
        official(r.source.source_url, c.vendor);
        const b = r.scope_binding;
        if (b) {
          const row = b.source.source_locator,
            locator = r.source.source_locator;
          if (
            !sourceIdentity(b.source, c.source) ||
            !sourceIdentity(b.source, r.source) ||
            b.cve_id !== c.cve_id ||
            row !== c.source.source_locator
          )
            fail('remediation source and CVE scope');
          if (b.basis === 'same_source_row' && !(locator === row || locator.startsWith(row + '/')))
            fail('same row remediation locator');
        }
        if (r.product_ids.length && c.product_id !== null && !r.product_ids.includes(c.product_id))
          fail('remediation product scope');
        if (
          (!r.product_ids.length || c.product_id === null) &&
          !b &&
          !c.issues.includes('remediation_product_scope_unresolved')
        )
          fail('unresolved remediation scope issue');
        for (const [key, code] of [
          ['published_availability', 'availability_statement_missing'],
          ['publisher_id', 'remediation_publisher_id_missing'],
          ['availability_date', 'availability_date_missing'],
        ])
          missing(c.issues, r[key], code);
      }
      if (c.bundle) {
        official(c.bundle.source.source_url, c.vendor);
        if (!c.bundle.member_advisory_ids.includes(c.advisory_id))
          fail('explicit bundle membership');
        missing(c.issues, c.bundle.published_at, 'bundle_publication_date_missing');
      }
      for (const r of c.vendor_severity || []) {
        official(r.source.source_url, c.vendor);
        if (r.vendor !== c.vendor || r.advisory_id !== c.advisory_id)
          fail('vendor rating advisory scope');
        for (const key of ['scheme', 'namespace'])
          missing(r.issues, r[key], 'vendor_severity_' + key + '_missing');
      }
      for (const s of c.scores) {
        official(s.source.source_url, c.vendor, true);
        if (s.scope === 'cve_specific' && (s.cve_id === null || s.cve_id !== c.cve_id))
          fail('score CVE scope');
        if (s.product_ids.length && !s.product_ids.includes(c.product_id))
          fail('score product scope');
        missing(c.issues, s.value, 'score_value_missing');
        if (s.scope === 'unresolved' && !c.issues.includes('score_scope_unresolved'))
          fail('unresolved score scope issue');
      }
    }
    if (!scoped) reviewedSections(evidence.claims);
    for (const r of evidence.score_availability || []) {
      official(r.source_url, r.vendor);
      if (r.source) {
        official(r.source.source_url, r.vendor);
        if (r.source.source_url !== r.source_url) fail('score availability representation');
      }
      if (r.attempts.some((a) => a.cve_id !== r.cve_id)) fail('score attempt CVE scope');
    }
    for (const c of evidence.coverage) {
      official(c.source_url, c.vendor);
      const e = c.enumeration;
      if (
        e &&
        (e.definition_sha256 !== evidence.definition_sha256 ||
          e.window.start_date > e.window.end_date)
      )
        fail('enumeration definition/window');
      for (const [key, code] of [
        ['total', 'publisher_total_unknown'],
        ['observed_start', 'observation_start_unknown'],
        ['observed_end', 'observation_end_unknown'],
      ])
        missing(c.issues, c[key], code);
      if (c.observed_start !== null && c.observed_end !== null && c.observed_start > c.observed_end)
        fail('coverage observation window');
    }
  }
  function evidenceStream(evidence, study) {
    const seen = new Set(),
      reviewed = [];
    let bytes = 0;
    return {
      get bytes() {
        return bytes;
      },
      add(c) {
        validate('switching-evidence-v1.json', c, '/$defs/claim');
        evidenceSemantics(
          { ...evidence, claims: [c], coverage: [], score_availability: [] },
          study,
          true,
        );
        if (seen.has(c.claim_id)) fail('deterministic unique claim IDs');
        const identityCost = c.claim_id.length + 3;
        if (identityCost > 128000000 - bytes) fail('study semantic accumulator byte budget');
        seen.add(c.claim_id);
        bytes += identityCost;
        if (
          (c.vendor === 'arista' && c.advisory_id === '19904-security-advisory-0100') ||
          c.remediations.some((r) => r.scope_binding?.basis === 'reviewed_source_sections')
        ) {
          const cost = window.InfrastructureJSON.measure(c, null, '', 128000000 - bytes);
          bytes += cost;
          reviewed.push(c);
        }
        if (bytes > 128000000) fail('study semantic accumulator byte budget');
      },
      finish() {
        reviewedSections(reviewed);
        evidenceSemantics({ ...evidence, claims: [], score_availability: [] }, study);
      },
    };
  }
  function full(report) {
    validate('switching-comparison-v1.json', report);
    const hash = definition(report);
    if (report.availability === 'available') {
      if (!report.inputs) fail('missing full inputs');
      for (const input of [report.inputs.evidence, report.inputs.kev]) identity(input, report);
      if (report.inputs.evidence.definition_sha256 !== hash) fail('input definition fingerprint');
      evidenceSemantics(report.inputs.evidence, report.definition);
    }
    return report;
  }
  window.InfrastructureSwitchingContracts = {
    validate,
    fingerprint,
    full,
    summary,
    header,
    evidenceStream,
    identity,
  };
})();
