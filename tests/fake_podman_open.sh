#!/usr/bin/env bash
# Fast stateful Podman stand-in for open-lifecycle shell tests.
set -euo pipefail
: "${ASF_FAKE_PODMAN_STATE:?}"
: "${MOCK_LOG:?}"
STATE=$ASF_FAKE_PODMAN_STATE
mkdir -p "$STATE"
printf 'podman %s\n' "$*" >> "$MOCK_LOG"

write_value() { printf '%s' "$2" > "$STATE/$1"; }
read_value() { [[ -f "$STATE/$1" ]] && cat "$STATE/$1" || true; }
remove_value() { rm -f "$STATE/$1"; }

label_filter() {
    local key="$1" arg next=false
    shift
    for arg in "$@"; do
        if [[ "$next" == true ]]; then
            case "$arg" in label="$key"=*) printf '%s' "${arg#label=$key=}"; return 0 ;; esac
            next=false
        elif [[ "$arg" == --filter ]]; then
            next=true
        fi
    done
}

container_for_filters() {
    local session role agent wanted
    session=$(label_filter asf.session "$@")
    role=$(label_filter asf.role "$@")
    agent=$(label_filter asf.agent "$@")
    if [[ -n "$session" ]]; then
        [[ -f "$STATE/runtime_exists" ]] || return 0
        [[ "$(read_value runtime_session)" == "$session" ]] && printf '%s\n' agent-test-container
        return 0
    fi
    if [[ -n "$role" ]]; then
        [[ -f "$STATE/${role}_exists" ]] || return 0
        wanted=$(read_value "${role}_agent")
        [[ -z "$agent" || "$wanted" == "$agent" ]] && read_value "${role}_name" && printf '\n'
    fi
}

json_labels() {
    local ref="$1" role name agent sandbox session
    if [[ "$ref" == agent-test-container ]]; then
        session=$(read_value runtime_session)
        printf '"asf.session":"%s"' "$session"
        return
    fi
    for role in proxy broker routed-gateway routed-init; do
        name=$(read_value "${role}_name")
        if [[ -n "$name" && ( "$ref" == "$name" || "$ref" == "${name}-id" ) ]]; then
            agent=$(read_value "${role}_agent")
            sandbox=$(read_value "${role}_sandbox")
            printf '"asf.role":"%s","asf.agent":"%s","asf.sandbox":"%s"' "$role" "$agent" "$sandbox"
            return
        fi
    done
}

container_exists() {
    local ref="$1" role name
    [[ "$ref" == agent-test-container && -f "$STATE/runtime_exists" ]] && return 0
    for role in proxy broker routed-gateway routed-init; do
        name=$(read_value "${role}_name")
        [[ -f "$STATE/${role}_exists" && ( "$ref" == "$name" || "$ref" == "${name}-id" ) ]] && return 0
    done
    return 1
}

remove_container() {
    local ref="$1" role name
    if [[ "$ref" == agent-test-container || "$ref" == stale-agent-container ]]; then
        remove_value runtime_exists
        return
    fi
    for role in proxy broker routed-gateway routed-init; do
        name=$(read_value "${role}_name")
        if [[ "$ref" == "$name" || "$ref" == "${name}-id" ]]; then
            remove_value "${role}_exists"
            return
        fi
    done
}

case "${1:-}" in
    __add-runtime)
        write_value runtime_session "${2:?}"
        : > "$STATE/runtime_exists"
        ;;
    ps)
        container_for_filters "$@"
        ;;
    inspect)
        shift
        [[ "${1:-}" == --type ]] && shift 2
        refs=("$@")
        for ref in "${refs[@]}"; do
            if ! container_exists "$ref"; then
                echo "Error: no such container $ref" >&2
                exit 125
            fi
        done
        printf '['
        first=true
        for ref in "${refs[@]}"; do
            [[ "$first" == true ]] || printf ','
            first=false
            printf '{"Id":"%s","Name":"%s","State":{"Status":"running","Running":true},"Config":{"Image":"fake:test","Labels":{' "$ref" "$ref"
            json_labels "$ref"
            printf '}},"NetworkSettings":{"Networks":{}},"HostConfig":{"ReadonlyRootfs":false}}'
        done
        printf ']\n'
        ;;
    run)
        input=""
        for arg in "$@"; do
            if [[ "$arg" == -i ]]; then
                input=$(cat || true)
                break
            fi
        done
        text="$* $input"
        name="" role="" agent="" sandbox=""
        previous=""
        for arg in "$@"; do
            if [[ "$previous" == --name ]]; then name="$arg"; fi
            if [[ "$previous" == --label ]]; then
                case "$arg" in
                    asf.role=*) role=${arg#asf.role=} ;;
                    asf.agent=*) agent=${arg#asf.agent=} ;;
                    asf.sandbox=*) sandbox=${arg#asf.sandbox=} ;;
                esac
            fi
            case "$arg" in
                --name=*) name=${arg#--name=} ;;
                --label=asf.role=*) role=${arg#--label=asf.role=} ;;
                --label=asf.agent=*) agent=${arg#--label=asf.agent=} ;;
                --label=asf.sandbox=*) sandbox=${arg#--label=asf.sandbox=} ;;
            esac
            previous="$arg"
        done
        if [[ -n "$name" && -n "$role" ]]; then
            write_value "${role}_name" "$name"
            write_value "${role}_agent" "$agent"
            write_value "${role}_sandbox" "$sandbox"
            : > "$STATE/${role}_exists"
        fi
        if [[ "${MOCK_PROBE_INFRA_FAIL:-false}" == true && "$text" == *"-probe:v2"* ]]; then exit 125; fi
        case "$text" in
            *"route show default"*"asf-route-probe"*) exit 22 ;;
            *"asf-probe-response"*"GET http://"*:9000/*)
                if [[ "${MOCK_PORT_ENFORCED:-true}" == true ]]; then
                    printf 'HTTP/1.1 403 Forbidden\n'
                    exit 40
                fi
                printf 'HTTP/1.1 200 OK\n'
                exit 20
                ;;
            *"asf-probe-response"*"CONNECT statsig.com:443"*|*"asf-probe-response"*"CONNECT github.com:443"*|*"asf-probe-response"*"CONNECT pypi.org:443"*)
                if [[ "${MOCK_CONNECT_OK:-true}" == true ]]; then
                    printf 'HTTP/1.1 200 Connection Established\n'
                    exit 20
                fi
                exit 61
                ;;
            *"asf-probe-response"*"CONNECT "*)
                printf 'HTTP/1.1 403 Forbidden\n'
                exit 40
                ;;
            *"ip -4 route show default"*|*"ip -6 route show default"*) exit 0 ;;
            *"ip -4 route get 1.1.1.1"*) echo "RTNETLINK answers: Network is unreachable" >&2; exit 1 ;;
            *nslookup*) exit 1 ;;
            *"GET http://"*:9000/*)
                if [[ "${MOCK_PORT_ENFORCED:-true}" == true ]]; then
                    printf 'HTTP/1.1 403 Forbidden\r\n\r\n'
                else
                    printf 'HTTP/1.1 200 OK\r\n\r\n'
                fi
                exit 0
                ;;
            *"CONNECT statsig.com:443"*|*"CONNECT github.com:443"*|*"CONNECT pypi.org:443"*)
                [[ "${MOCK_CONNECT_OK:-true}" == true ]] || exit 1
                printf 'HTTP/1.1 200 Connection Established\r\n\r\n'; exit 0 ;;
            *"CONNECT "*) printf 'HTTP/1.1 403 Forbidden\r\n\r\n'; exit 0 ;;
            *" 4000"*) exit 0 ;;
            *"nc "*) exit 1 ;;
            *) exit 0 ;;
        esac
        ;;
    rm)
        shift
        skip=false
        for arg in "$@"; do
            if [[ "$skip" == true ]]; then skip=false; continue; fi
            if [[ "$arg" == --time || "$arg" == -t ]]; then skip=true; continue; fi
            [[ "$arg" == -* ]] || remove_container "$arg"
        done
        ;;
    stop|exec|info|version|image|pull|build|logs)
        if [[ "${1:-}" == info ]]; then echo 'true netavark'; fi
        if [[ "${1:-}" == version ]]; then echo '5.0.0-fake'; fi
        exit 0
        ;;
    network)
        action=${2:-}; shift 2 || true
        case "$action" in
            create)
                if [[ -n "${ASF_EXPECT_RUNTIME_PLAN:-}" && ! -f "$ASF_EXPECT_RUNTIME_PLAN" ]]; then
                    echo "runtime plan was not written before network creation" >&2
                    exit 99
                fi
                name=${!#}
                grep -qxF "$name" "$STATE/networks" 2>/dev/null || echo "$name" >> "$STATE/networks"
                ;;
            inspect) grep -qxF "${1:-}" "$STATE/networks" 2>/dev/null || { echo 'Error: no such network' >&2; exit 125; } ;;
            exists)
                if grep -qxF "${1:-}" "$STATE/networks" 2>/dev/null; then
                    exit 0
                fi
                exit 1
                ;;
            rm) for name in "$@"; do [[ "$name" == -* ]] || sed -i "\|^${name}$|d" "$STATE/networks" 2>/dev/null || true; done ;;
        esac
        ;;
    secret)
        action=${2:-}; shift 2 || true
        case "$action" in
            ls) cat "$STATE/secrets" 2>/dev/null || true ;;
            create)
                secret_name=""; skip=false
                for arg in "$@"; do
                    if [[ "$skip" == true ]]; then skip=false; continue; fi
                    if [[ "$arg" == --driver ]]; then skip=true; continue; fi
                    [[ "$arg" == -* ]] || { secret_name="$arg"; break; }
                done
                [[ -z "$secret_name" ]] || echo "$secret_name" >> "$STATE/secrets"
                ;;
            inspect) grep -qxF "${1:-}" "$STATE/secrets" 2>/dev/null || { echo 'Error: no such secret' >&2; exit 125; } ;;
            rm) for name in "$@"; do sed -i "\|^${name}$|d" "$STATE/secrets" 2>/dev/null || true; done ;;
        esac
        ;;
    volume)
        action=${2:-}; shift 2 || true
        case "$action" in
            inspect) grep -qxF "${1:-}" "$STATE/volumes" 2>/dev/null || { echo 'Error: no such volume' >&2; exit 125; } ;;
            rm) for name in "$@"; do sed -i "\|^${name}$|d" "$STATE/volumes" 2>/dev/null || true; done ;;
        esac
        ;;
    *) exit 0 ;;
esac
