manual_evidence_keys() {
    printf '%s\n' authz idor session api_fuzzing logging_review threat_model_review
}

has_pr5_configuration() {
    [[ -n "$OPENAPI_SPEC" || -n "$API_FUZZING_REVIEW" || -n "$API_BASE_URL" || -n "$AUTH_HEADER_NAME" ]]
}

has_api_fuzzing_review() {
    [[ -n "$API_FUZZING_REVIEW" ]]
}

manual_evidence_path() {
    case "$1" in
        authz) printf '%s\n' "$AUTHZ_MATRIX" ;;
        idor) printf '%s\n' "$IDOR_REVIEW" ;;
        session) printf '%s\n' "$SESSION_REVIEW" ;;
        api_fuzzing) printf '%s\n' "$API_FUZZING_REVIEW" ;;
        logging_review) printf '%s\n' "$LOGGING_REVIEW" ;;
        threat_model_review) printf '%s\n' "$THREAT_MODEL_REVIEW" ;;
        *) return 1 ;;
    esac
}

manual_evidence_hint() {
    case "$1" in
        authz) printf '%s\n' 'add --authz-matrix' ;;
        idor) printf '%s\n' 'add --idor-review' ;;
        session) printf '%s\n' 'add --session-review' ;;
        api_fuzzing) printf '%s\n' 'add --api-fuzzing-review' ;;
        logging_review) printf '%s\n' 'add --logging-review' ;;
        threat_model_review) printf '%s\n' 'add --threat-model-review' ;;
        *) return 1 ;;
    esac
}

manual_evidence_plan_label() {
    printf '%s (host)\n' "$(manual_evidence_tool_name "$1")"
}

manual_evidence_enabled() {
    [[ -n "$(manual_evidence_path "$1")" ]]
}

manual_evidence_tool_name() {
    case "$1" in
        authz) printf '%s\n' 'authz-matrix' ;;
        idor) printf '%s\n' 'idor-review' ;;
        session) printf '%s\n' 'session-security' ;;
        api_fuzzing) printf '%s\n' 'api-fuzzing' ;;
        logging_review) printf '%s\n' 'logging-review' ;;
        threat_model_review) printf '%s\n' 'threat-model-review' ;;
        *) return 1 ;;
    esac
}

manual_evidence_skip_note() {
    case "$1" in
        authz) printf '%s\n' 'sin --authz-matrix' ;;
        idor) printf '%s\n' 'sin --idor-review' ;;
        session) printf '%s\n' 'sin --session-review' ;;
        api_fuzzing) printf '%s\n' 'sin --api-fuzzing-review' ;;
        logging_review) printf '%s\n' 'sin --logging-review' ;;
        threat_model_review) printf '%s\n' 'sin --threat-model-review' ;;
        *) return 1 ;;
    esac
}

manual_evidence_readiness() {
    local key="$1" output_ready="$2"
    if manual_evidence_enabled "$key" && [[ "$output_ready" == READY ]]; then
        printf 'READY|-\n'
    elif [[ "$key" == "api_fuzzing" ]] && has_pr5_configuration; then
        printf 'CONFIGURING|%s\n' "$(manual_evidence_hint "$key")"
    elif [[ "$output_ready" == READY ]]; then
        printf 'CONFIGURING|%s\n' "$(manual_evidence_hint "$key")"
    else
        printf 'MISSING|%s\n' "$(manual_evidence_hint "$key")"
    fi
}

run_manual_evidence_step() {
    local key="$1"
    case "$key" in
        authz)
            local q_authz_matrix q_reports q_authz_script
            q_authz_matrix="$(printf '%q' "$AUTHZ_MATRIX")"
            q_reports="$(printf '%q' "$REPORTS_DIR")"
            q_authz_script="$(printf '%q' "${SCRIPT_DIR}/authz_matrix.py")"
            run_host "authz-matrix" "python3 ${q_authz_script} ${q_authz_matrix} ${q_reports}"
            return "$?"
            ;;
        idor)
            local rc
            progress "idor-review"
            cp "$IDOR_REVIEW" "${REPORTS_DIR}/F5/A01-idor-review.md"
            rc="$?"
            progress_done "$rc"
            write_status "idor-review" "host" "$rc" "copy IDOR review to F5/A01-idor-review.md"
            return "$rc"
            ;;
        session)
            local q_session_review q_reports q_session_script session_command safe_session_review_name
            q_session_review="$(printf '%q' "$SESSION_REVIEW")"
            q_reports="$(printf '%q' "$REPORTS_DIR")"
            q_session_script="$(printf '%q' "${SCRIPT_DIR}/session_security.py")"
            session_command="python3 ${q_session_script} ${q_session_review} ${q_reports}"
            safe_session_review_name="$(printf '%s' "$(basename -- "$SESSION_REVIEW")" | tr -cd '[:alnum:]_.-')"
            [[ -n "$safe_session_review_name" ]] || safe_session_review_name="session-review.json"
            run_host "session-security" "$session_command" "python3 session_security.py ${safe_session_review_name} reports"
            return "$?"
            ;;
        api_fuzzing)
            local q_review q_reports q_script safe_api_review_name safe_auth_header_name api_fuzz_command
            q_review="$(printf '%q' "$API_FUZZING_REVIEW")"
            q_reports="$(printf '%q' "$REPORTS_DIR")"
            q_script="$(printf '%q' "${SCRIPT_DIR}/api_fuzzing.py")"
            safe_api_review_name="$(printf '%s' "$(basename -- "$API_FUZZING_REVIEW")" | tr -cd '[:alnum:]_.-')"
            [[ -n "$safe_api_review_name" ]] || safe_api_review_name="api-fuzzing-review.json"
            safe_auth_header_name="$(printf '%s' "$AUTH_HEADER_NAME" | tr -cd '[:alnum:]_-')"
            api_fuzz_command="python3 ${q_script} ${q_review} ${q_reports}"
            run_host "api-fuzzing" "$api_fuzz_command" "python3 api_fuzzing.py ${safe_api_review_name} header=${safe_auth_header_name} value=[REDACTED]"
            return "$?"
            ;;
        logging_review)
            local q_review q_reports q_script safe_review_name command
            q_review="$(printf '%q' "$LOGGING_REVIEW")"
            q_reports="$(printf '%q' "$REPORTS_DIR")"
            q_script="$(printf '%q' "${SCRIPT_DIR}/logging_review.py")"
            safe_review_name="$(printf '%s' "$(basename -- "$LOGGING_REVIEW")" | tr -cd '[:alnum:]_.-')"
            [[ -n "$safe_review_name" ]] || safe_review_name="logging-review.json"
            command="python3 ${q_script} ${q_review} ${q_reports}"
            run_host "logging-review" "$command" "python3 logging_review.py ${safe_review_name} reports"
            return "$?"
            ;;
        threat_model_review)
            local q_review q_reports q_script safe_review_name command
            q_review="$(printf '%q' "$THREAT_MODEL_REVIEW")"
            q_reports="$(printf '%q' "$REPORTS_DIR")"
            q_script="$(printf '%q' "${SCRIPT_DIR}/threat_model_review.py")"
            safe_review_name="$(printf '%s' "$(basename -- "$THREAT_MODEL_REVIEW")" | tr -cd '[:alnum:]_.-')"
            [[ -n "$safe_review_name" ]] || safe_review_name="threat-model-review.json"
            command="python3 ${q_script} ${q_review} ${q_reports}"
            run_host "threat-model-review" "$command" "python3 threat_model_review.py ${safe_review_name} reports"
            return "$?"
            ;;
    esac
    return 0
}

run_or_skip_manual_evidence() {
    local key="$1" tool_name skip_note
    tool_name="$(manual_evidence_tool_name "$key")"
    if manual_evidence_enabled "$key"; then
        run_manual_evidence_step "$key"
        return "$?"
    fi
    skip_note="$(manual_evidence_skip_note "$key")"
    printf '  %s: omitido (%s)\n' "$tool_name" "$skip_note"
    write_status "$tool_name" "skipped" "0" "omitido; ${skip_note}"
    return 0
}

api_fuzzing_review_requires_active_dast() {
    python3 "${SCRIPT_DIR}/api_fuzzing.py" --requires-active-dast "$API_FUZZING_REVIEW" >/dev/null 2>&1
    case "$?" in
        0) printf 'true\n' ;;
        1) printf 'false\n' ;;
        *) die "no se pudo evaluar active_dast en api-fuzzing-review: $API_FUZZING_REVIEW" ;;
    esac
}
