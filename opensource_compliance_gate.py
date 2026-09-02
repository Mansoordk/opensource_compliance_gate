# v0.1.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *

import json
import typing


class OpenSourceComplianceGate(gl.Contract):
    """
    Open-source release compliance gate built for GenLayer.

    The contract evaluates the actual source and license evidence
    contained in a pinned GitHub repository commit.

    GenLayer validators independently retrieve the same pinned
    repository evidence and independently perform the compliance
    analysis before consensus is reached.

    Decision states:

        READY_FOR_REVIEW
        UNDER_REVIEW
        COMPLIANT
        NON_COMPLIANT
        HUMAN_REVIEW

    The contract is designed to be reusable across multiple
    software releases and projects.
    """

    # ------------------------------------------------------------------
    # Persistent contract state
    # ------------------------------------------------------------------

    repository_url: str
    project_license_policy: str
    maintainer: str

    current_commit: str
    current_release: str

    current_status: str
    has_resolved: bool

    compliance_score: u32

    detected_license: str
    license_risk: str

    evidence_summary: str
    decision_summary: str

    review_count: u32
    last_reviewed_commit: str

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(
        self,
        repository_url: str,
        project_license_policy: str,
        maintainer_address: str
    ):
        """
        Register a GitHub repository and its release compliance policy.

        Example repository:
            https://github.com/owner/repository

        Example policy:
            Allow permissive licenses such as MIT, Apache-2.0,
            BSD-2-Clause and BSD-3-Clause. Copyleft licenses such
            as GPL or AGPL require human review before release.
        """

        if not repository_url.strip():
            raise gl.vm.UserError(
                "Repository URL cannot be empty."
            )

        if not repository_url.startswith(
            "https://github.com/"
        ):
            raise gl.vm.UserError(
                "Repository must use a public GitHub HTTPS URL."
            )

        if not project_license_policy.strip():
            raise gl.vm.UserError(
                "License policy cannot be empty."
            )

        if not maintainer_address.strip():
            raise gl.vm.UserError(
                "Maintainer address cannot be empty."
            )

        self.repository_url = repository_url.rstrip("/")
        self.project_license_policy = project_license_policy
        self.maintainer = maintainer_address

        self.current_commit = ""
        self.current_release = ""

        self.current_status = "READY_FOR_REVIEW"
        self.has_resolved = False

        self.compliance_score = 0

        self.detected_license = ""
        self.license_risk = ""

        self.evidence_summary = (
            "No release has been submitted for compliance review."
        )

        self.decision_summary = ""

        self.review_count = 0
        self.last_reviewed_commit = ""

    # ------------------------------------------------------------------
    # Internal authorization helper
    # ------------------------------------------------------------------

    def _require_maintainer(self) -> None:
        """
        Restrict lifecycle-changing operations to the registered
        maintainer.
        """

        caller = str(gl.message.sender_address).lower()
        expected = str(self.maintainer).lower()

        if caller != expected:
            raise gl.vm.UserError(
                "Only the registered maintainer can perform this action."
            )

    # ------------------------------------------------------------------
    # GitHub URL helper
    # ------------------------------------------------------------------

    def _build_raw_url(
        self,
        path: str,
        commit: str
    ) -> str:
        """
        Convert:

            https://github.com/owner/repository

        into:

            https://raw.githubusercontent.com/owner/repository/
            <commit>/<path>

        The commit SHA pins the evidence to an immutable repository
        version.
        """

        base = self.repository_url

        if base.endswith("/"):
            base = base[:-1]

        github_prefix = "https://github.com/"

        if not base.startswith(github_prefix):
            raise gl.vm.UserError(
                "Invalid GitHub repository URL."
            )

        repository_path = base[len(github_prefix):]

        return (
            "https://raw.githubusercontent.com/"
            + repository_path
            + "/"
            + commit
            + "/"
            + path
        )

    # ------------------------------------------------------------------
    # Submit release
    # ------------------------------------------------------------------

    @gl.public.write
    def submit_release(
        self,
        release_label: str,
        source_commit: str
    ) -> typing.Any:
        """
        Submit a specific repository commit for compliance review.

        Only the maintainer may submit a release.

        The commit SHA is stored before the non-deterministic
        verification begins, so the exact source version being
        evaluated is explicit.
        """

        self._require_maintainer()

        if self.current_status == "UNDER_REVIEW":
            raise gl.vm.UserError(
                "A release is already undergoing compliance review."
            )

        if not release_label.strip():
            raise gl.vm.UserError(
                "Release label cannot be empty."
            )

        if not source_commit.strip():
            raise gl.vm.UserError(
                "Source commit cannot be empty."
            )

        if len(source_commit.strip()) < 7:
            raise gl.vm.UserError(
                "Source commit must contain a valid commit identifier."
            )

        self.current_release = release_label.strip()
        self.current_commit = source_commit.strip()

        self.current_status = "UNDER_REVIEW"
        self.has_resolved = False

        self.compliance_score = 0

        self.detected_license = ""
        self.license_risk = ""

        self.evidence_summary = (
            "Release submitted. Awaiting independent source-grounded "
            "compliance verification."
        )

        self.decision_summary = ""

        return {
            "status": self.current_status,
            "release": self.current_release,
            "commit": self.current_commit
        }

    # ------------------------------------------------------------------
    # Source-grounded compliance review
    # ------------------------------------------------------------------

    @gl.public.write
    def review_release(self) -> typing.Any:
        """
        Retrieve the pinned repository source and perform a
        decentralized compliance analysis.

        Validators independently execute the same source retrieval
        and analysis. They must agree on the substantive decision,
        risk classification and evidence availability.
        """

        self._require_maintainer()

        if self.current_status != "UNDER_REVIEW":
            raise gl.vm.UserError(
                "No release is currently awaiting compliance review."
            )

        repository = self.repository_url
        commit = self.current_commit
        policy = self.project_license_policy
        release = self.current_release

        def collect_and_analyze() -> typing.Any:
            """
            Non-deterministic evidence collection and analysis.

            Every validator independently executes this function.
            """

            # ----------------------------------------------------------
            # Candidate license files
            # ----------------------------------------------------------

            license_paths = [
                "LICENSE",
                "LICENSE.md",
                "LICENSE.txt",
                "COPYING",
                "COPYING.md"
            ]

            license_evidence = []

            for path in license_paths:
                url = self._build_raw_url(
                    path,
                    commit
                )

                try:
                    response = gl.nondet.web.get(url)

                    if response.status_code == 200:
                        body = response.body.decode("utf-8")

                        if body.strip():
                            # Keep evidence bounded so the LLM input
                            # remains practical.
                            license_evidence.append(
                                "FILE: "
                                + path
                                + "\n"
                                + body[:12000]
                            )
                except Exception:
                    # A missing/unavailable candidate file is not
                    # automatically treated as compliance.
                    pass

            # ----------------------------------------------------------
            # Common project metadata files
            # ----------------------------------------------------------

            metadata_paths = [
                "pyproject.toml",
                "package.json",
                "Cargo.toml",
                "go.mod",
                "README.md"
            ]

            metadata_evidence = []

            for path in metadata_paths:
                url = self._build_raw_url(
                    path,
                    commit
                )

                try:
                    response = gl.nondet.web.get(url)

                    if response.status_code == 200:
                        body = response.body.decode("utf-8")

                        if body.strip():
                            metadata_evidence.append(
                                "FILE: "
                                + path
                                + "\n"
                                + body[:10000]
                            )
                except Exception:
                    pass

            # ----------------------------------------------------------
            # Evidence requirement
            # ----------------------------------------------------------

            if len(license_evidence) == 0:
                return {
                    "decision": "HUMAN_REVIEW",
                    "score": 0,
                    "risk": "UNKNOWN",
                    "license": "UNDETERMINED",
                    "evidence_found": False,
                    "summary": (
                        "No recognized license file could be retrieved "
                        "from the pinned repository commit."
                    )
                }

            license_text = "\n\n--- LICENSE EVIDENCE ---\n".join(
                license_evidence
            )

            metadata_text = "\n\n--- PROJECT METADATA ---\n".join(
                metadata_evidence
            )

            # ----------------------------------------------------------
            # Source-grounded AI analysis
            # ----------------------------------------------------------

            task = f"""
You are a decentralized software release compliance analyst.

You must determine whether a software release satisfies the
license policy supplied by the project maintainer.

IMPORTANT SOURCE RULES:

1. Base your decision ONLY on the repository evidence supplied
   below.

2. Do NOT assume a license merely from the repository name,
   filename, project name, or programming language.

3. Do NOT invent licenses for dependencies when their actual
   license evidence is not present.

4. If the available evidence is insufficient to determine
   compliance reliably, return HUMAN_REVIEW.

5. The source commit is pinned and must be treated as the exact
   release being reviewed.

PROJECT:
{repository}

RELEASE:
{release}

PINNED COMMIT:
{commit}

MAINTAINER LICENSE POLICY:
{policy}

ACTUAL LICENSE FILE EVIDENCE:
{license_text}

PROJECT METADATA EVIDENCE:
{metadata_text}

DECISION RULES:

COMPLIANT:
Use this only when the retrieved evidence clearly identifies
a license and that license satisfies the maintainer's policy.

NON_COMPLIANT:
Use this only when the retrieved evidence clearly identifies
a license that violates the stated policy.

HUMAN_REVIEW:
Use this when:
- license evidence is contradictory,
- the license cannot be reliably identified,
- the policy cannot be applied reliably,
- evidence is incomplete,
- or the available source does not justify a confident decision.

SCORING:

90-100:
Clear compliance with strong source evidence.

70-89:
Likely compliant but some minor uncertainty exists.

40-69:
Material uncertainty or mixed licensing evidence.

1-39:
Strong evidence of non-compliance.

0:
No sufficient evidence / human review required.

Return ONLY valid JSON using exactly this structure:

{{
    "decision": "COMPLIANT",
    "score": 95,
    "risk": "LOW",
    "license": "MIT",
    "evidence_found": true,
    "summary": "Short factual explanation based only on retrieved evidence."
}}

Allowed decision values:

COMPLIANT
NON_COMPLIANT
HUMAN_REVIEW

Allowed risk values:

LOW
MEDIUM
HIGH
UNKNOWN

Do not include markdown.
Do not include additional fields.
Do not provide reasoning outside the JSON object.
"""

            try:
                raw_result = gl.nondet.exec_prompt(task)

                cleaned = (
                    raw_result
                    .replace("```json", "")
                    .replace("```", "")
                    .strip()
                )

                parsed = json.loads(cleaned)

            except Exception:
                return {
                    "decision": "HUMAN_REVIEW",
                    "score": 0,
                    "risk": "UNKNOWN",
                    "license": "UNDETERMINED",
                    "evidence_found": False,
                    "summary": (
                        "The compliance analysis could not be "
                        "reliably parsed."
                    )
                }

            # ----------------------------------------------------------
            # Validate result structure
            # ----------------------------------------------------------

            if not isinstance(parsed, dict):
                return {
                    "decision": "HUMAN_REVIEW",
                    "score": 0,
                    "risk": "UNKNOWN",
                    "license": "UNDETERMINED",
                    "evidence_found": False,
                    "summary": "Invalid compliance analysis response."
                }

            decision = parsed.get("decision")
            score = parsed.get("score")
            risk = parsed.get("risk")
            license_name = parsed.get("license")
            evidence_found = parsed.get("evidence_found")
            summary = parsed.get("summary")

            if decision not in [
                "COMPLIANT",
                "NON_COMPLIANT",
                "HUMAN_REVIEW"
            ]:
                decision = "HUMAN_REVIEW"

            if risk not in [
                "LOW",
                "MEDIUM",
                "HIGH",
                "UNKNOWN"
            ]:
                risk = "UNKNOWN"

            if not isinstance(score, int):
                score = 0

            if score < 0:
                score = 0

            if score > 100:
                score = 100

            if not isinstance(evidence_found, bool):
                evidence_found = False

            if not isinstance(license_name, str):
                license_name = "UNDETERMINED"

            if not isinstance(summary, str):
                summary = "No reliable compliance summary available."

            # Conservative safety rule.
            if not evidence_found:
                decision = "HUMAN_REVIEW"
                risk = "UNKNOWN"
                score = 0

            return {
                "decision": decision,
                "score": score,
                "risk": risk,
                "license": license_name,
                "evidence_found": evidence_found,
                "summary": summary[:2000]
            }

        # --------------------------------------------------------------
        # Independent validator consensus
        # --------------------------------------------------------------

        def validator_fn(leader_result) -> bool:
            """
            Validators independently retrieve the same pinned source
            and independently perform the compliance analysis.

            The validator does NOT simply check the leader's JSON
            formatting.
            """

            if not isinstance(
                leader_result,
                gl.vm.Return
            ):
                return False

            leader_data = leader_result.calldata

            try:
                validator_data = collect_and_analyze()
            except Exception:
                return False

            # ----------------------------------------------------------
            # Decision must match exactly.
            # ----------------------------------------------------------

            if (
                leader_data.get("decision")
                != validator_data.get("decision")
            ):
                return False

            # ----------------------------------------------------------
            # Evidence availability must match.
            # ----------------------------------------------------------

            if (
                leader_data.get("evidence_found")
                != validator_data.get("evidence_found")
            ):
                return False

            # ----------------------------------------------------------
            # Risk classification must match.
            # ----------------------------------------------------------

            if (
                leader_data.get("risk")
                != validator_data.get("risk")
            ):
                return False

            # ----------------------------------------------------------
            # License identity should be substantively consistent.
            #
            # We compare normalized license strings rather than
            # free-form summaries.
            # ----------------------------------------------------------

            leader_license = str(
                leader_data.get(
                    "license",
                    ""
                )
            ).strip().lower()

            validator_license = str(
                validator_data.get(
                    "license",
                    ""
                )
            ).strip().lower()

            if leader_license != validator_license:
                return False

            # ----------------------------------------------------------
            # Scores are subjective, so allow a reasonable tolerance.
            # A large disagreement should force another validator
            # rather than silently accepting it.
            # ----------------------------------------------------------

            try:
                leader_score = int(
                    leader_data.get("score", 0)
                )

                validator_score = int(
                    validator_data.get("score", 0)
                )

                if abs(
                    leader_score - validator_score
                ) > 10:
                    return False

            except Exception:
                return False

            return True

        # --------------------------------------------------------------
        # Execute GenLayer consensus.
        # --------------------------------------------------------------

        result = gl.vm.run_nondet_unsafe(
            collect_and_analyze,
            validator_fn
        )

        decision = result["decision"]
        score = result["score"]
        risk = result["risk"]
        license_name = result["license"]
        evidence_found = result["evidence_found"]
        summary = result["summary"]

        # --------------------------------------------------------------
        # Deterministic state transition.
        # --------------------------------------------------------------

        self.compliance_score = u32(score)

        self.detected_license = license_name
        self.license_risk = risk

        self.evidence_summary = (
            "Pinned commit: "
            + self.current_commit
            + ". Evidence available: "
            + str(evidence_found)
            + ". Detected license: "
            + license_name
            + "."
        )

        self.decision_summary = summary

        self.review_count = self.review_count + u32(1)

        self.last_reviewed_commit = self.current_commit

        if decision == "COMPLIANT":
            self.current_status = "COMPLIANT"
            self.has_resolved = True

        elif decision == "NON_COMPLIANT":
            self.current_status = "NON_COMPLIANT"
            self.has_resolved = True

        else:
            self.current_status = "HUMAN_REVIEW"
            self.has_resolved = False

        return {
            "decision": decision,
            "score": score,
            "risk": risk,
            "license": license_name,
            "evidence_found": evidence_found,
            "summary": summary,
            "status": self.current_status,
            "commit": self.current_commit
        }

    # ------------------------------------------------------------------
    # Safe retry / reset
    # ------------------------------------------------------------------

    @gl.public.write
    def reset_for_new_release(self) -> typing.Any:
        """
        Safely return a completed or disputed review to a state where
        the maintainer can submit another pinned release.

        This does NOT modify the repository or policy configuration.
        """

        self._require_maintainer()

        if self.current_status == "UNDER_REVIEW":
            raise gl.vm.UserError(
                "Cannot reset while a compliance review is active."
            )

        if self.current_status not in [
            "COMPLIANT",
            "NON_COMPLIANT",
            "HUMAN_REVIEW"
        ]:
            raise gl.vm.UserError(
                "The contract is already ready for a new release."
            )

        self.current_status = "READY_FOR_REVIEW"
        self.has_resolved = False

        self.current_release = ""
        self.current_commit = ""

        self.compliance_score = 0

        self.detected_license = ""
        self.license_risk = ""

        self.evidence_summary = (
            "Previous review completed. Ready for a new pinned release."
        )

        self.decision_summary = ""

        return {
            "status": self.current_status,
            "message": (
                "Contract reset successfully. "
                "Maintainer may submit a new release."
            )
        }

    # ------------------------------------------------------------------
    # Public registry state
    # ------------------------------------------------------------------

    @gl.public.view
    def get_registry_state(
        self
    ) -> dict[str, typing.Any]:
        """
        Return the persistent compliance registry state.
        """

        return {
            "repository": self.repository_url,
            "policy": self.project_license_policy,
            "maintainer": self.maintainer,

            "current_release": self.current_release,
            "current_commit": self.current_commit,

            "current_status": self.current_status,
            "has_resolved": self.has_resolved,

            "compliance_score": self.compliance_score,
            "detected_license": self.detected_license,
            "license_risk": self.license_risk,

            "evidence_summary": self.evidence_summary,
            "decision_summary": self.decision_summary,

            "review_count": self.review_count,
            "last_reviewed_commit": self.last_reviewed_commit
        }

    # ------------------------------------------------------------------
    # Public current-review information
    # ------------------------------------------------------------------

    @gl.public.view
    def get_compliance_result(
        self
    ) -> dict[str, typing.Any]:
        """
        Return the latest compliance result and evidence summary.
        """

        return {
            "repository": self.repository_url,
            "release": self.current_release,
            "commit": self.current_commit,

            "status": self.current_status,
            "resolved": self.has_resolved,

            "score": self.compliance_score,
            "detected_license": self.detected_license,
            "risk": self.license_risk,

            "evidence_summary": self.evidence_summary,
            "decision_summary": self.decision_summary
        }

    # ------------------------------------------------------------------
    # Future upgrades
    # ------------------------------------------------------------------

    @gl.public.write
    def upgrade(
        self,
        new_code: bytes
    ) -> None:
        """
        Upgrade the contract code while preserving persistent storage.

        GenLayer's Root storage controls the authorized upgrader list.
        The upgraded implementation must preserve the existing
        storage layout.
        """

        root = gl.storage.Root.get()

        code = root.code.get()

        code.truncate()

        code.extend(new_code)
