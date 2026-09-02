#!/usr/bin/env bash
# Three-round ASF review loop: Codex -> Claude -> Codex.
#
# The host owns Git/worktree state and round transitions. Agents get the task
# worktree read-write and host-generated Git evidence read-only. ASF's normal
# framework checkout remains read-only; nothing is merged or pushed automatically.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: tools/ai-review-loop.sh <task-slug> <prompt-file> [base-ref]

Creates ai/<task-slug> in a sibling linked worktree and runs:
  1. Codex / GPT-5.6 Sol implementation
  2. Claude / Opus review and justified fixes
  3. Codex / GPT-5.6 Sol final audit

The host commits each round. Model-produced commits use the model as Git
author while the host's configured Git identity remains the committer. The
selected sandboxed gate runs once on the untouched base before model rounds and
again after them; by default it only checks the SBOM. Set ASF_REVIEW_GATE for a
focused command. The worktree and branch remain for human review. Full
regressions belong in CI.

Environment overrides:
  ASF_REVIEW_CODEX_MODEL   Codex model (default: gpt-5.6-sol)
  ASF_REVIEW_CLAUDE_MODEL  Claude model (default: claude-opus-5)
  ASF_REVIEW_GATE          Final sandboxed gate command
                           (default: python3 tools/generate_sbom.py --check)
  ASF_REVIEW_BASELINE      Set to 1 when a focused gate is knowingly red at
                           the base; only matching pre-existing unittest
                           FAIL/ERROR names are ignored (default: unset)
  ASF_REVIEW_REFRESH       Sandboxed derived-file refresh after round 3
                           (default: python3 tools/generate_sbom.py; set empty to skip)
  ASF_REVIEW_CLAUDE_MAX_TURNS
                           Claude review turn limit (default: 40). This is a
                           runaway stop, not a budget; ASF_REVIEW_TIMEOUT
                           bounds the round.
  ASF_REVIEW_TIMEOUT       Per-round/gate timeout (default: 30m)
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ ${1:-} != "--help" && ${1:-} != "-h" ]] || { usage; exit 0; }
[[ $# -ge 2 && $# -le 3 ]] || { usage >&2; exit 2; }

slug=$1
prompt_file=$2
base_ref=${3:-HEAD}
codex_model=${ASF_REVIEW_CODEX_MODEL:-gpt-5.6-sol}
claude_model=${ASF_REVIEW_CLAUDE_MODEL:-claude-opus-5}
gate_command=${ASF_REVIEW_GATE:-python3 tools/generate_sbom.py --check}
refresh_command=${ASF_REVIEW_REFRESH-python3 tools/generate_sbom.py}
baseline_mode=${ASF_REVIEW_BASELINE:-}
baseline_rc=0
review_timeout=${ASF_REVIEW_TIMEOUT:-30m}
claude_max_turns=${ASF_REVIEW_CLAUDE_MAX_TURNS:-40}
heartbeat_seconds=30

[[ -z $baseline_mode || $baseline_mode == 1 ]] || \
    die "ASF_REVIEW_BASELINE must be unset or 1"
[[ $claude_max_turns =~ ^[1-9][0-9]*$ ]] || \
    die "ASF_REVIEW_CLAUDE_MAX_TURNS must be a positive integer"

[[ $slug =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || \
    die "task slug must use only letters, numbers, '.', '_' or '-'"
[[ -f $prompt_file ]] || die "prompt file not found: $prompt_file"
[[ -s $prompt_file ]] || die "prompt file is empty: $prompt_file"
command -v python3 >/dev/null 2>&1 || die "python3 is required on the host"
command -v timeout >/dev/null 2>&1 || die "timeout is required on the host"

root=$(git rev-parse --show-toplevel 2>/dev/null) || \
    die "run this from the ASF Git repository"
root=$(cd "$root" && pwd -P)
[[ -x $root/sandbox.sh ]] || die "ASF launcher not found at $root/sandbox.sh"
[[ -z $(git -C "$root" status --porcelain=v1 --untracked-files=all) ]] || \
    die "main ASF checkout must be clean; commit or stash changes first"
stream_helper="$root/tools/ai-review-stream.py"
[[ -x $stream_helper ]] || die "review stream helper not found: $stream_helper"

base_commit=$(git -C "$root" rev-parse --verify "${base_ref}^{commit}" 2>/dev/null) || \
    die "base ref does not resolve to a commit: $base_ref"
repo_parent=$(dirname "$root")
repo_base=$(basename "$root")
worktree="$repo_parent/${repo_base}-ai-${slug}"
evidence="$repo_parent/${repo_base}-ai-${slug}-evidence"
agent_evidence="$evidence/${repo_base}-ai-${slug}-input"
branch="ai/${slug}"
repo_name=$(basename "$worktree")
agent_evidence_name=$(basename "$agent_evidence")
task_path="/workspace/repos/$repo_name"
evidence_path="/workspace/repos/$agent_evidence_name"
baseline_failures="$evidence/gate-failures-base.txt"
final_failures="$evidence/gate-failures-final.txt"
usage_jsonl="$evidence/usage.jsonl"
usage_text="$evidence/usage.txt"

[[ ! -e $worktree ]] || die "worktree path already exists: $worktree"
[[ ! -e $evidence ]] || die "evidence path already exists: $evidence"
if git -C "$root" show-ref --verify --quiet "refs/heads/$branch"; then
    die "branch already exists: $branch"
fi

printf 'ASF AI review loop\n'
printf '  base:      %s (%s)\n' "$base_ref" "${base_commit:0:12}"
printf '  branch:    %s\n' "$branch"
printf '  worktree:  %s\n' "$worktree"
printf '  evidence:  %s\n' "$evidence"
printf '  Codex:     %s\n' "$codex_model"
printf '  Claude:    %s\n' "$claude_model"
printf '  gate:      %s\n' "$gate_command"
if [[ -n $refresh_command ]]; then
    printf '  refresh:   %s\n' "$refresh_command"
else
    printf '  refresh:   disabled\n'
fi
printf '  timeout:   %s per round\n' "$review_timeout"
printf '  turn cap:  Claude %s\n' "$claude_max_turns"
[[ -z $baseline_mode ]] || printf '  baseline:  known-red attribution enabled\n'
printf '\n'

git -C "$root" worktree add "$worktree" -b "$branch" "$base_commit"
git -C "$root" worktree lock "$worktree" --reason "ai-review loop in progress"
mkdir -m 0700 "$evidence"
mkdir -m 0700 "$agent_evidence"
original_task="$agent_evidence/original-task.txt"
cat -- "$prompt_file" > "$original_task"
chmod 0600 "$original_task"

# Linked worktrees use a small .git pointer into host-managed Git state. Keep
# that pointer entirely outside untrusted agent turns; agents get host-generated
# Git evidence read-only instead.
[[ -f $worktree/.git && ! -L $worktree/.git ]] || \
    die "unexpected linked-worktree .git layout"
git_pointer=$(cat "$worktree/.git")
git_pointer_hidden=false

hide_git_pointer() {
    [[ -d $worktree && ! -L $worktree ]] || \
        die "task worktree was replaced; inspect $worktree"
    [[ -f $worktree/.git && ! -L $worktree/.git ]] || \
        die "linked-worktree .git pointer is missing or invalid; inspect $worktree"
    [[ $(cat "$worktree/.git" 2>/dev/null || true) == "$git_pointer" ]] || \
        die "linked-worktree .git pointer changed; inspect $worktree"
    rm -f -- "$worktree/.git"
    git_pointer_hidden=true
}

restore_git_pointer() {
    [[ -d $worktree && ! -L $worktree ]] || \
        die "task worktree was replaced; inspect $worktree"
    if [[ -e $worktree/.git || -L $worktree/.git ]]; then
        die "agent created .git while Git metadata was hidden; inspect $worktree"
    fi
    printf '%s\n' "$git_pointer" > "$worktree/.git"
    git_pointer_hidden=false
}

best_effort_restore_git_pointer() {
    [[ ${git_pointer_hidden:-false} == true ]] || return 0
    if [[ -d $worktree && ! -L $worktree \
          && ! -e $worktree/.git && ! -L $worktree/.git ]]; then
        printf '%s\n' "$git_pointer" > "$worktree/.git" 2>/dev/null || true
        return 0
    fi
    printf 'WARNING: refusing to restore .git automatically; inspect %s\n' \
        "$worktree" >&2
}

mounts=()
cleanup_mounts() {
    local spec agent name
    for spec in "${mounts[@]}"; do
        agent=${spec%%:*}
        name=${spec#*:}
        "$root/sandbox.sh" repo remove "$agent" "$name" >/dev/null 2>&1 || true
    done
}

print_cleanup_commands() {
    printf '  git -C %q worktree unlock %q\n' "$root" "$worktree"
    printf '  git -C %q worktree remove %q\n' "$root" "$worktree"
    printf '  git -C %q branch -D %q\n' "$root" "$branch"
    printf '  rm -rf %q\n' "$evidence"
}

cleanup() {
    local rc=$1
    best_effort_restore_git_pointer
    cleanup_mounts
    if (( rc != 0 )) && [[ -d $worktree ]]; then
        printf '\nReview state retained after failure:\n' >&2
        printf '  worktree: %s\n' "$worktree" >&2
        printf '  evidence: %s\n' "$evidence" >&2
        printf '\nTo remove this failed review:\n' >&2
        print_cleanup_commands >&2
    fi
}
trap 'rc=$?; cleanup "$rc"' EXIT

add_mount() {
    local agent=$1 path=$2 mode=$3
    "$root/sandbox.sh" repo add "$agent" "$path" --mode "$mode"
    mounts+=("$agent:$(basename "$path")")
}

add_mount codex "$worktree" rw
add_mount codex "$agent_evidence" ro
add_mount claude "$worktree" rw
add_mount claude "$agent_evidence" ro

refresh_evidence() {
    printf '%s\n' "$base_commit" > "$agent_evidence/base-commit.txt"
    git -C "$worktree" log --oneline --decorate "$base_commit"..HEAD \
        > "$agent_evidence/log.txt"
    git -C "$worktree" status --short > "$agent_evidence/status.txt"
    git -C "$worktree" --no-pager diff --no-ext-diff --text \
        "$base_commit"...HEAD > "$agent_evidence/diff.patch"
    git -C "$worktree" --no-pager show --no-ext-diff --stat --oneline HEAD \
        > "$agent_evidence/show.txt"
}

write_round_prompt() {
    local round=$1 path=$2
    case "$round" in
        codex-1)
            cat > "$path" <<'PROMPT'
You are round 1, the implementation agent in a three-round ASF review loop.

The original task follows after the separator below. Inspect the existing code
and focused tests first. Implement the smallest correct change. Keep code simple,
clean, efficient and auditable. Run only focused tests that materially
validate the changed behavior. Do not run repository-wide test discovery or the
full test suite during the model round; full regressions belong in CI.

Stay inside the task's stated scope. Do not change shipped defaults, manifests
or documented behavior the task did not ask you to change, and do not weaken or
delete an existing test assertion to make a change pass. If the task contains an
open question, do not implement an answer unless explicitly requested; report it
under "Open questions" in your final message.

The host owns Git. Git metadata is deliberately unavailable inside this sandbox.
Do not create .git, commit, push, reset, or depend on Git commands. Work only in
the current task repository.

--- ORIGINAL TASK ---
PROMPT
            cat "$original_task" >> "$path"
            ;;
        claude-2)
            cat > "$path" <<PROMPT
You are round 2, an independent reviewer/fixer in a three-round ASF review loop.

Read the original task below. Host-generated Git evidence is authoritative and
is available read-only at:
  $evidence_path

Work in this order:
  1. Read log.txt, show.txt, status.txt and diff.patch.
  2. Judge the change against the original task: correctness, security, scope
     creep, and whether every edit to an existing test is justified by an
     intended behavior change rather than by a broken assertion.
  3. Open task files only where a concrete issue in the diff requires it.
  4. Fix real issues directly and verify each fix with a focused test that
     covers it.
  5. Finish with a short verdict: what you changed and why, or that no fix was
     needed.

base-gate.txt records the gate the host already ran on the untouched base
commit; it is your baseline. Any test named there was already failing before
this branch. Do not investigate it unless the task or current diff directly
targets that behavior. Full regressions, baseline attribution, and derived files
such as the SBOM belong to the host and CI, so spend no turns reproducing them.

Keep the review proportional to the diff, decide without asking for approval,
and finish as soon as the change is either sound or fixed.

The host owns Git. Git metadata is deliberately unavailable inside this sandbox.
Do not create .git, commit, push, reset, or depend on Git commands.

--- ORIGINAL TASK ---
PROMPT
            cat "$original_task" >> "$path"
            ;;
        codex-3)
            cat > "$path" <<PROMPT
You are round 3, the final audit agent in a three-round ASF review loop.

Read the original task below and independently inspect the host-generated Git
evidence at:
  $evidence_path
Start with diff.patch, status.txt, show.txt, and log.txt. This is a final audit
of the task change, not a general audit of ASF or of the review-loop machinery.
Keep the effort proportional to the diff. Inspect additional files only when a
concrete issue in the change requires it. Look for regressions, security
weakening, scope creep beyond the task, weakened or deleted test assertions,
missed edge cases, and over-engineering. Fix only real problems and run focused
tests only when they materially validate the changed behavior.

base-gate.txt records the gate the host already ran on the untouched base
commit; it is your baseline. Any test named there was already failing before
this branch. Do not investigate it unless the task or current diff directly
targets that behavior. Full regressions, baseline attribution, and derived files
such as the SBOM belong to the host and CI, so spend no turns reproducing them.
If the evidence establishes correctness, finish without extra exploration.

The host owns Git. Git metadata is deliberately unavailable inside this sandbox.
Do not create .git, commit, push, reset, or depend on Git commands.

--- ORIGINAL TASK ---
PROMPT
            cat "$original_task" >> "$path"
            ;;
        *) die "unknown review round: $round" ;;
    esac
    chmod 0600 "$path"
}

show_answer() {
    local answer=$1
    printf '      answer:\n'
    if [[ -s $answer ]]; then
        sed 's/^/        /' "$answer"
    else
        printf '        (no final answer captured)\n'
    fi
}

show_round_usage() {
    local round=$1 line
    line=$(python3 "$stream_helper" summarize --usage "$usage_jsonl" \
        | grep -E "^round ${round} ·" | tail -n 1 || true)
    [[ -z $line ]] || printf '      usage: %s\n' "$line"
}

run_structured_round() {
    local round=$1 agent=$2 title=$3
    shift 3
    local prefix="$evidence/round-${round}-${agent}"
    local jsonl="${prefix}.jsonl"
    local runtime_log="${prefix}-runtime.log"
    local answer="${prefix}-answer.md"
    local statuses run_rc parser_rc

    printf '\n[%s/3] %s\n' "$round" "$title"
    hide_git_pointer

    set +e
    timeout --signal=TERM --kill-after=30s "$review_timeout" \
        "$root/sandbox.sh" run "$agent" -- "$@" </dev/null 2>&1 \
        | python3 "$stream_helper" stream \
            --agent "$agent" \
            --round "$round" \
            --jsonl "$jsonl" \
            --runtime-log "$runtime_log" \
            --answer "$answer" \
            --usage "$usage_jsonl" \
            --heartbeat "$heartbeat_seconds"
    statuses=("${PIPESTATUS[@]}")
    set -e

    run_rc=${statuses[0]}
    parser_rc=${statuses[1]}
    restore_git_pointer

    if (( run_rc != 0 || parser_rc != 0 )); then
        if (( run_rc == 124 )); then
            printf '      ! round timed out after %s\n' "$review_timeout" >&2
        else
            printf '      ! round failed (agent=%s, stream=%s)\n' \
                "$run_rc" "$parser_rc" >&2
        fi
        printf '      runtime tail (%s):\n' "$runtime_log" >&2
        tail -n 30 "$runtime_log" | sed 's/^/        /' >&2 || true
        return 1
    fi

    show_answer "$answer"
    show_round_usage "$round"
    printf '      logs: %s, %s\n' "$jsonl" "$runtime_log"
}

run_codex() {
    local round=$1 prompt_path=$2 title=$3
    run_structured_round "$round" codex "$title" \
        codex exec \
        --json \
        --ephemeral \
        --skip-git-repo-check \
        --sandbox workspace-write \
        -C "$task_path" \
        --model "$codex_model" \
        "Read $prompt_path and follow those instructions."
}

run_claude() {
    local round=$1 prompt_path=$2 title=$3
    run_structured_round "$round" claude "$title" \
        /usr/bin/env --chdir="$task_path" \
        claude -p \
        --output-format stream-json \
        --verbose \
        --max-turns "$claude_max_turns" \
        --no-session-persistence \
        --permission-mode bypassPermissions \
        --add-dir "$evidence_path" \
        --tools "Bash,Edit,Write,Read,Glob,Grep" \
        --model "$claude_model" \
        "Read $prompt_path and follow those instructions."
}

run_sandbox_command() {
    local log=$1 command=$2 rc
    hide_git_pointer

    set +e
    timeout --signal=TERM --kill-after=30s "$review_timeout" \
        "$root/sandbox.sh" run codex -- \
        /usr/bin/env --chdir="$task_path" \
        bash -e -u -o pipefail -c "$command" \
        </dev/null >"$log" 2>&1
    rc=$?
    set -e
    restore_git_pointer
    return "$rc"
}

run_gate_command() {
    run_sandbox_command "$1" "$gate_command"
}

check_gate_clean() {
    local label=$1 status
    git -C "$worktree" clean -fdX --quiet
    status=$(git -C "$worktree" status --porcelain=v1 --untracked-files=all)
    if [[ -n $status ]]; then
        printf '      ! %s modified the reviewed worktree:\n' "$label" >&2
        printf '%s\n' "$status" | sed 's/^/        /' >&2
        return 1
    fi
}

# Standard unittest prints one header per failing test. Baseline attribution is
# deliberately limited to that stable identifier; other gate formats remain
# plain pass/fail rather than being guessed at.
gate_failures() {
    grep -E '^(ERROR|FAIL): .+' "$1" | sort -u || true
}


# Agents reconstruct a baseline when they are not given one. Publishing the
# host's base-gate result removes the reason to reverse-apply the diff or run
# repository-wide discovery inside a review round.
write_base_gate_evidence() {
    local rc=$1 log=$2 path="$agent_evidence/base-gate.txt"
    {
        printf 'command: %s\n' "$gate_command"
        printf 'base:    %s\n' "$base_commit"
        printf 'exit:    %s\n' "$rc"
        if (( rc == 0 )); then
            printf 'result:  clean on the base commit\n'
        else
            printf 'result:  red on the base commit; the tests named below were\n'
            printf '         already failing before this branch\n'
            gate_failures "$log"
        fi
    } > "$path"
    chmod 0600 "$path"
}

run_preflight_gate() {
    local log="$evidence/gate-preflight.log" rc=0
    printf '\n[base] Sandboxed preflight gate on %s\n' "${base_commit:0:12}"
    printf '      command: %s\n' "$gate_command"
    run_gate_command "$log" || rc=$?
    check_gate_clean "base preflight gate" || return 1

    if (( rc != 0 )); then
        if (( rc == 124 )); then
            printf '      ! base preflight timed out after %s\n' "$review_timeout" >&2
        else
            printf '      ! base preflight failed (exit %s); no model rounds were started\n' "$rc" >&2
        fi
        printf '      runtime tail (%s):\n' "$log" >&2
        tail -n 40 "$log" | sed 's/^/        /' >&2 || true
        return 1
    fi

    write_base_gate_evidence "$rc" "$log"
    printf '      ✓ base gate passes\n'
    printf '      log: %s\n' "$log"
}

capture_baseline() {
    local log="$evidence/gate-baseline.log" rc=0 count
    printf '\n[base] Sandboxed baseline gate on %s\n' "${base_commit:0:12}"
    printf '      command: %s\n' "$gate_command"
    run_gate_command "$log" || rc=$?
    baseline_rc=$rc
    check_gate_clean "baseline gate" || return 1

    if (( rc == 0 )); then
        : > "$baseline_failures"
        write_base_gate_evidence "$rc" "$log"
        printf '      ✓ baseline passes\n'
        printf '      log: %s\n' "$log"
        return 0
    fi
    if (( rc == 124 )); then
        printf '      ! baseline gate timed out after %s\n' "$review_timeout" >&2
        return 1
    fi

    gate_failures "$log" > "$baseline_failures"
    count=$(wc -l < "$baseline_failures")
    if (( count == 0 )); then
        printf '      ! baseline gate failed (exit %s), but no unittest FAIL/ERROR names were found\n' "$rc" >&2
        printf '        cannot attribute later failures safely; see %s\n' "$log" >&2
        return 1
    fi

    write_base_gate_evidence "$rc" "$log"
    printf '      recorded %s pre-existing unittest failure(s) (exit %s)\n' "$count" "$rc"
    printf '      failures: %s\n' "$baseline_failures"
    printf '      log: %s\n' "$log"
}

run_gate() {
    local log="$evidence/gate-runtime.log" rc=0 new
    printf '\n[gate] Sandboxed final gate\n'
    printf '      command: %s\n' "$gate_command"
    run_gate_command "$log" || rc=$?
    check_gate_clean "final gate" || return 1

    if (( rc != 0 )) && [[ -n $baseline_mode && -s $baseline_failures \
          && $rc -eq $baseline_rc ]]; then
        gate_failures "$log" > "$final_failures"
        if [[ -s $final_failures ]]; then
            new=$(comm -13 "$baseline_failures" "$final_failures")
            if [[ -z $new ]]; then
                printf '      ✓ only pre-existing unittest failures remain\n'
                printf '      baseline: %s\n' "$baseline_failures"
                printf '      log: %s\n' "$log"
                return 0
            fi
            printf '      ! failures introduced by this branch:\n%s\n' "$new" >&2
        fi
    fi

    if (( rc != 0 )); then
        if (( rc == 124 )); then
            printf '      ! gate timed out after %s\n' "$review_timeout" >&2
        else
            printf '      ! gate failed (exit %s)\n' "$rc" >&2
        fi
        printf '      runtime tail (%s):\n' "$log" >&2
        tail -n 40 "$log" | sed 's/^/        /' >&2 || true
        return 1
    fi

    printf '      ✓ gate passed\n'
    printf '      log: %s\n' "$log"
}

refresh_derived() {
    local log="$evidence/refresh-runtime.log" rc=0 status

    [[ -n $refresh_command ]] || return 0

    printf '\n[derived] Sandboxed refresh\n'
    printf '      command: %s\n' "$refresh_command"
    run_sandbox_command "$log" "$refresh_command" || rc=$?
    if (( rc != 0 )); then
        if (( rc == 124 )); then
            printf '      ! derived refresh timed out after %s\n' "$review_timeout" >&2
        else
            printf '      ! derived refresh failed (exit %s)\n' "$rc" >&2
        fi
        printf '      runtime tail (%s):\n' "$log" >&2
        tail -n 40 "$log" | sed 's/^/        /' >&2 || true
        return 1
    fi

    git -C "$worktree" clean -fdX --quiet
    status=$(git -C "$worktree" status --porcelain=v1 --untracked-files=all)
    if [[ -z $status ]]; then
        printf '      ✓ derived files already up to date\n'
        printf '      log: %s\n' "$log"
        return 0
    fi

    commit_round "chore: refresh derived files for $slug" "ASF Review Loop" "ai-review@localhost"
    refresh_evidence
    printf '      ✓ derived files refreshed and committed\n'
    printf '      log: %s\n' "$log"
}

commit_round() {
    local message=$1 author_name=$2 author_email=$3
    # Keep Git as the authoritative handoff: discard ignored scratch/cache files
    # that would otherwise survive a round without appearing in normal evidence.
    git -C "$worktree" clean -fdX --quiet
    git -C "$worktree" add -A
    git -C "$worktree" \
        -c commit.gpgsign=false \
        -c core.hooksPath=/dev/null \
        commit --no-verify --allow-empty \
        --author="$author_name <$author_email>" -m "$message"
}

# Preserve meaningful partial work from a failed round, but do not add an empty
# failure commit when the agent changed nothing.
abort_round() {
    local round=$1 label=$2 author_name=$3 author_email=$4 status
    show_round_usage "$round"
    git -C "$worktree" clean -fdX --quiet
    status=$(git -C "$worktree" status --porcelain=v1 --untracked-files=all)
    if [[ -n $status ]]; then
        commit_round "ai-review: $label for $slug (round $round failed)" \
            "$author_name" "$author_email"
        printf '      partial changes committed for inspection\n'
    else
        printf '      no task-tree changes to commit from the failed round\n'
    fi
    refresh_evidence
    die "round $round failed; review state retained on $branch"
}

round1_prompt="$agent_evidence/round-1-prompt.txt"
round2_prompt="$agent_evidence/round-2-prompt.txt"
round3_prompt="$agent_evidence/round-3-prompt.txt"

if [[ -n $baseline_mode ]]; then
    capture_baseline
else
    run_preflight_gate
fi

write_round_prompt codex-1 "$round1_prompt"
run_codex 1 "$evidence_path/round-1-prompt.txt" "Codex implementation" || \
    abort_round 1 "codex implementation" "Codex via ASF" "codex@localhost"
commit_round "ai-review: codex implementation for $slug" "Codex via ASF" "codex@localhost"
refresh_evidence

write_round_prompt claude-2 "$round2_prompt"
run_claude 2 "$evidence_path/round-2-prompt.txt" "Claude review" || \
    abort_round 2 "claude review" "Claude via ASF" "claude@localhost"
commit_round "ai-review: claude review for $slug" "Claude via ASF" "claude@localhost"
refresh_evidence

write_round_prompt codex-3 "$round3_prompt"
run_codex 3 "$evidence_path/round-3-prompt.txt" "Codex final audit" || \
    abort_round 3 "codex final audit" "Codex via ASF" "codex@localhost"
commit_round "ai-review: codex final audit for $slug" "Codex via ASF" "codex@localhost"
refresh_evidence

refresh_derived

# Host-side Git checks inspect repository data but execute no task code.
git -C "$worktree" --no-pager diff --no-ext-diff --check "$base_commit"...HEAD
run_gate
refresh_evidence

python3 "$stream_helper" summarize --usage "$usage_jsonl" > "$usage_text"

printf '\n✓ AI review completed. Nothing was merged or pushed.\n'
printf '  branch:   %s\n' "$branch"
printf '  evidence: %s\n' "$evidence"
printf '\nUsage:\n'
sed 's/^/  /' "$usage_text"
printf '\nReview worktree:\n'
printf '  cd %q\n' "$worktree"
printf '\nInspect:\n'
printf '  git status\n'
printf '  git log --oneline --decorate %q..HEAD\n' "$base_commit"
printf '  git diff %q...HEAD\n' "$base_commit"
printf '\nIf you accept the result, from the branch you want to update:\n'
printf '  cd %q\n' "$root"
printf '  git status\n'
printf '  git merge --no-ff %q\n' "$branch"
if git -C "$root" remote get-url origin >/dev/null 2>&1; then
    printf '\nOr push the review branch first to run full regressions in CI:\n'
    printf '  git -C %q push -u origin %q\n' "$root" "$branch"
else
    printf '\nCI push command omitted: no origin remote is configured.\n'
fi
printf '\nIf you reject the result:\n'
print_cleanup_commands
