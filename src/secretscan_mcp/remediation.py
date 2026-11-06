"""What to do about a leaked secret. Everything here is TEXT: nothing is executed."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .detect import RULES_BY_ID, Finding
from .scanner import HistoryScan, TreeScan


@dataclass(frozen=True)
class Provider:
    name: str
    what: str
    rotate: tuple[str, ...]
    check: str  # how to see whether it was used


PROVIDERS: dict[str, Provider] = {
    "aws": Provider(
        "AWS",
        "An IAM access key ID (AKIA... long-lived, ASIA... temporary STS) or the secret half that goes with it. "
        "Together they sign API calls as an IAM user or role.",
        (
            "In the IAM console open the user > Security credentials > Create access key, and deploy the new key.",
            "Deactivate the leaked key first, then delete it once nothing breaks: "
            "`aws iam update-access-key --user-name <USER> --access-key-id <KEY_ID> --status Inactive`, then "
            "`aws iam delete-access-key --user-name <USER> --access-key-id <KEY_ID>`.",
            "For ASIA (temporary) keys: IAM > role > Revoke active sessions, or attach an inline policy that denies "
            "everything issued before now.",
            "Prefer roles (IAM Identity Center, OIDC for CI, instance profiles) so no long-lived key exists to leak.",
        ),
        "CloudTrail event history: `aws cloudtrail lookup-events --lookup-attributes "
        "AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>`. Also check for new IAM users, EC2 instances in "
        "unusual regions, and the billing dashboard. AWS may already have applied the AWSCompromisedKeyQuarantine policy.",
    ),
    "github": Provider(
        "GitHub",
        "A GitHub token (ghp_ personal, gho_ OAuth, ghu_/ghs_ app, ghr_ refresh, github_pat_ fine-grained). "
        "It acts as the user or app that owns it, with that token's scopes.",
        (
            "Personal tokens: GitHub > Settings > Developer settings > Personal access tokens > delete the token, "
            "then create a replacement with the minimum scopes and an expiry.",
            "OAuth tokens: revoke the app's authorization under Settings > Applications.",
            "App installation tokens (ghs_) expire after 1 hour, but rotate the app's private key if that leaked too.",
            "GitHub secret scanning may already have revoked a token pushed to a public repository; check anyway.",
        ),
        "Settings > Security log (user) or the organization audit log: look for repository access, clones, "
        "new deploy keys, new tokens and workflow changes made with this token.",
    ),
    "gitlab": Provider(
        "GitLab",
        "A GitLab personal access token (glpat-). It acts as its owner with the token's scopes.",
        (
            "User settings > Access tokens > Revoke the token, then create a new one with minimal scopes and an expiry.",
            "Or use the API: POST /personal_access_tokens/:id/rotate issues a replacement and revokes the old one.",
        ),
        "User settings > Authentication log, and the project/group audit events for changes made around the leak.",
    ),
    "slack": Provider(
        "Slack",
        "A Slack bot/user token (xoxb-, xoxp-, ...) or an incoming-webhook URL. "
        "A token can read and post as the app; a webhook can post into its channel.",
        (
            "Tokens: api.slack.com/apps > your app > OAuth & Permissions > rotate or revoke the token "
            "(or call the auth.revoke method), then reinstall if needed.",
            "Webhooks: app > Incoming Webhooks > remove the leaked webhook URL and add a new one.",
            "Slack revokes tokens it detects in public GitHub repositories automatically; confirm rather than assume.",
        ),
        "Workspace admin > Analytics / Access logs for the app's activity.",
    ),
    "stripe": Provider(
        "Stripe",
        "A Stripe secret (sk_) or restricted (rk_) API key. Live keys can move real money; test keys cannot.",
        (
            "Dashboard > Developers > API keys > the key's menu > Roll key. Choose an expiry for the old key "
            "(immediately, if you suspect abuse).",
            "Use restricted keys with only the permissions the service needs.",
        ),
        "Dashboard > Developers > Logs and Events: look for requests you do not recognise, refunds, payouts and new webhook endpoints.",
    ),
    "google": Provider(
        "Google Cloud",
        "A Google API key (AIza...). It bills your project for the APIs it can call and is not a login credential, "
        "but anyone holding it can spend your quota.",
        (
            "Cloud console > APIs and Services > Credentials > the key > Regenerate key (or create a new one and delete the old).",
            "Add API restrictions and application restrictions (HTTP referrer, IP or app) to the replacement.",
        ),
        "APIs and Services > Metrics and the Billing reports for unexpected usage.",
    ),
    "anthropic": Provider(
        "Anthropic",
        "An Anthropic API key (sk-ant-...). Whoever has it spends your account's credit.",
        (
            "Console > Settings > API keys > delete the leaked key and create a new one; store it in a secret manager "
            "or environment variable, not source.",
        ),
        "Console usage and cost pages for requests you did not make.",
    ),
    "openai": Provider(
        "OpenAI",
        "An OpenAI API key (sk-... / sk-proj-...). Whoever has it spends your account's credit.",
        (
            "Platform dashboard > API keys > revoke the leaked key and create a new one scoped to one project.",
        ),
        "Usage dashboard for requests you did not make; set a spend limit.",
    ),
    "npm": Provider(
        "npm",
        "An npm access token (npm_...). Depending on its type it can publish new versions of your packages.",
        (
            "npmjs.com > profile > Access tokens > delete the token (or `npm token list` then `npm token revoke <id>`).",
            "Create a replacement as a granular token limited to the packages and permissions it needs; "
            "prefer trusted publishing from CI.",
        ),
        "Check each package's published versions and `npm access` collaborators for changes you did not make.",
    ),
    "pypi": Provider(
        "PyPI",
        "A PyPI API token (pypi-...). It can upload releases to the projects it is scoped to (or all of yours).",
        (
            "pypi.org > Account settings > API tokens > Remove the token; create a project-scoped replacement, "
            "or switch to trusted publishing so no token exists.",
        ),
        "Each project's release history for uploads you did not make (and yank them if found).",
    ),
    "sendgrid": Provider(
        "SendGrid",
        "A SendGrid API key (SG....). It can send mail as your domain.",
        ("Settings > API Keys > delete the key and create a new one with restricted access.",),
        "Email Activity feed and sender authentication settings for mail you did not send.",
    ),
    "jwt": Provider(
        "JSON Web Token",
        "A signed token that proves identity or access until its exp claim passes. "
        "It is only as safe as the moment it was issued: anyone holding it can replay it.",
        (
            "Invalidate it at the issuer: log the session out / revoke the refresh token, or add its jti to a deny list.",
            "If the token is long-lived or you cannot revoke single tokens, rotate the signing key; that invalidates every token it signed.",
            "Do not paste it into an online decoder; decode it locally if you need to see its claims.",
        ),
        "The issuer's auth logs for the token's subject and unusual IPs after the leak.",
    ),
    "password": Provider(
        "Password in a connection URL",
        "A username and password embedded in a URL (database, message broker, FTP, git remote).",
        (
            "Change the password on the service itself (for example ALTER USER ... PASSWORD ...), "
            "then update the connection string wherever it is configured.",
            "Read the URL from an environment variable or secret manager instead of source, and restrict the "
            "service to the network ranges that need it.",
        ),
        "The service's connection and query logs for logins from addresses you do not know.",
    ),
    "private-key": Provider(
        "Private key",
        "A PEM private key. What it unlocks depends on what the key is for: SSH login, a TLS certificate, "
        "token or package signing, or encryption.",
        (
            "SSH key: remove the matching public key from every authorized_keys, GitHub/GitLab deploy key and CI secret; "
            "generate a new pair with `ssh-keygen -t ed25519`.",
            "TLS key: revoke the certificate with your CA and reissue it with a fresh key pair.",
            "Signing key (JWT, code, packages): rotate it, publish the new public key, and treat everything signed with the old key as suspect.",
        ),
        "Server auth logs for logins with that key; certificate transparency logs for certificates you did not request.",
    ),
    "generic": Provider(
        "Unidentified credential",
        "A value assigned to a name like password/secret/token/api_key that looks random (length, mixed character "
        "classes and entropy pass the filters). It is a hint, not proof: it may also be a test value.",
        (
            "Open the file at the reported line and work out which service the value belongs to.",
            "If it is real, rotate it at that service (use that provider's explain_finding entry if it matches one).",
            "If it is a test value or a false positive, add its fingerprint to .secretscan-ignore (see make_baseline).",
        ),
        "Whatever logs the owning service keeps.",
    ),
}

NOT_UN_LEAKED = (
    "Rewriting history does not un-leak a secret. Once a commit was pushed, assume it was copied: clones, forks, "
    "CI caches, pull-request refs, mirrors and scrapers (bots watch public pushes within seconds) may all hold it. "
    "Rotating or revoking the credential is the fix; removing it from history is housekeeping that comes after."
)


def explain_rule(rule_id: str, finding: Finding | None = None, extra: str = "") -> str:
    rule = RULES_BY_ID[rule_id]
    prov = PROVIDERS[rule.provider]
    lines = [f"{rule.title} ({rule.id}, severity {rule.severity})"]
    if finding is not None:
        loc = f"{finding.path}:{finding.line}"
        lines.append(f"Finding {finding.id}: {loc}, value {finding.preview}{extra}")
    lines += ["", f"What it is: {prov.what}", "", "How to rotate / revoke:"]
    lines += [f"  {i}. {step}" for i, step in enumerate(prov.rotate, 1)]
    lines += ["", f"Was it used? {prov.check}", "", NOT_UN_LEAKED]
    return "\n".join(lines)


# --- checklist --------------------------------------------------------------


def _q(path: str) -> str:
    return f'"{path}"' if re.search(r"[^\w./\-]", path) else path


def build_checklist(tree: TreeScan | None, hist: HistoryScan | None) -> str:
    tree_f = tree.findings if tree else []
    hist_f = hist.findings if hist else []
    rules = sorted({f.rule for f in tree_f} | {h.finding.rule for h in hist_f})
    files_tree = sorted({f.path for f in tree_f})
    files_hist = sorted({h.finding.path for h in hist_f})
    n = 0
    out: list[str] = []

    def step(title: str, *body: str) -> None:
        nonlocal n
        n += 1
        out.append(f"{n}. {title}")
        out.extend(f"   {b}" for b in body)
        out.append("")

    if not rules:
        out.append("No secrets were found, so there is nothing to rotate. Hygiene steps:\n")
        step("Check that secret files cannot be committed by accident", "Run check_gitignore.")
        step("Block future leaks", *_prevent())
        return "\n".join(out).rstrip()

    out.append("Remediation checklist (do these in order; this tool only prints text and runs none of it):\n")
    step(
        "ROTATE OR REVOKE every credential below, before anything else.",
        "Assume each one is compromised if it was ever pushed or shared. Details per type: explain_finding(<id or rule>).",
        *[f"- {RULES_BY_ID[r].title} ({r}): {PROVIDERS[RULES_BY_ID[r].provider].name}" for r in rules],
    )
    step("Look for misuse in the exposure window (first commit that contained it, until the rotation).",
         *[f"- {PROVIDERS[RULES_BY_ID[r].provider].name}: {PROVIDERS[RULES_BY_ID[r].provider].check}" for r in rules])
    if files_tree:
        step(
            "Take the secrets out of the working tree and load them from the environment or a secret manager.",
            *[f"- {p}" for p in files_tree],
            "Commit the removal. Add the file or a pattern to .gitignore if the file is meant to stay local.",
        )
    if files_hist:
        step(
            "(Optional hygiene) remove the secrets from git history. Rotation in step 1 is what actually protects you.",
            NOT_UN_LEAKED,
            "Work on a fresh mirror clone and keep a backup:  git clone --mirror <REPO_URL> repo-backup.git",
            "Files in history that held secrets: " + ", ".join(files_hist),
            "Option A - git filter-repo (https://github.com/newren/git-filter-repo), delete whole files:",
            *[f"    git filter-repo --invert-paths --path {_q(p)}" for p in files_hist],
            "Option A2 - git filter-repo, replace only the secret text. Create replacements.txt yourself, one line "
            "per secret in the form  <THE-SECRET-VALUE>==>***REMOVED***  (this tool never prints the value), then:",
            "    git filter-repo --replace-text replacements.txt",
            "Option B - BFG Repo-Cleaner (https://rtyley.github.io/bfg-repo-cleaner/):",
            *[f"    bfg --delete-files {_q(p.rsplit('/', 1)[-1])}" for p in files_hist],
            "    bfg --replace-text replacements.txt",
            "    git reflog expire --expire=now --all && git gc --prune=now --aggressive",
            "Then publish the rewrite and tell everyone to re-clone (old clones still contain the secret):",
            "    git push --force --all && git push --force --tags",
            "On GitHub, pull-request refs and cached commit views survive a force-push: ask GitHub Support to purge them.",
        )
    step("Check the result.", "Run scan_tree and scan_history again; remaining false positives can go in .secretscan-ignore (make_baseline).")
    step("Block future leaks", *_prevent())
    return "\n".join(out).rstrip()


def _prevent() -> tuple[str, ...]:
    return (
        "Turn on push protection / secret scanning in your git host (GitHub: Settings > Code security).",
        "Add a pre-commit hook that scans staged changes before they become history.",
        "Keep secrets in environment variables or a secret manager; commit only a .env.example with fake values.",
    )
