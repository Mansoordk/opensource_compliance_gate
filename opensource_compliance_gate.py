# v0.1.1
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *

import json
import typing


class OpenSourceComplianceGate(gl.Contract):
    """
    Source-grounded open-source license compliance gate for GenLayer.

    The contract registers a public GitHub repository and a license policy.
    A maintainer can submit a specific immutable commit for review.

    During review, GenLayer validators independently:

        1. Retrieve license evidence from the pinned GitHub commit.
        2. Retrieve supporting project metadata from the same commit.
        3. Analyze the retrieved evidence against the configured policy.
        4. Produce a structured compliance decision.
        5. Reach consensus through GenLayer's non-deterministic
           execution and equivalence validation.

    Possible review outcomes:

        COMPLIANT
        NON_COMPLIANT
        HUMAN_REVIEW

    Lifecycle:

        READY_FOR_REVIEW
            |
            v
        UNDER_REVIEW
          / | \
         /  |  \
        v   v   v
    COMPLIANT
    NON_COMPLIANT
    HUMAN_REVIEW
         |
         v
    READY_FOR_REVIEW

    The repository URL and project policy remain fixed after deployment.
    Each release is identified by an immutable Git commit SHA.
    """


    # ==============================================================
    # Persistent state
    # ==============================================================

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


    # ==============================================================
    # Constructor
    # ==============================================================

    def __init__(
        self,
        repository_url: str,
        project_license_policy: str,
        maintainer_address: str
    ):
        """
        Register the repository, license policy and authorized maintainer.
        """

        if not repository_url.strip():
            raise gl.vm.UserError(
                "Repository URL cannot be empty."
            )

        if not repository_url.startswith(
            "https://github.com/"
        ):
            raise gl.vm.UserError(
                "Repository must be a public GitHub HTTPS URL."
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
        self.project_license_policy = project_license_policy.strip()
        self.maintainer = maintainer_address.strip()

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


    # ==============================================================
    # Authorization
    # ==============================================================

    def _require_maintainer(self) -> None:
        """
        Only the configured maintainer may change the review lifecycle.
        """

        caller = str(
            gl.message.sender_address
        ).lower()

        expected = str(
            self.maintainer
        ).lower()

        if caller != expected:
            raise gl.vm.UserError(
                "Only the registered maintainer can perform this action."
            )


    # ==============================================================
    # GitHub URL construction
    # ==============================================================

    def _build_raw_url(
        self,
        path: str,
        commit: str
    ) -> str:
        """
        Build an immutable raw GitHub URL.

        Example:

        Repository:
            https://github.com/owner/repository

        Commit:
            abc123...

        File:
            LICENSE

        Result:

        https://raw.githubusercontent.com/owner/repository/
        abc123.../LICENSE
        """

        prefix = "https://github.com/"

        base = self.repository_url.rstrip("/")

        if not base.startswith(prefix):
            raise gl.vm.UserError(
                "Invalid GitHub repository URL."
            )

        repository_path = base[len(prefix):]

        return (
            "https://raw.githubusercontent.com/"
            + repository_path
            + "/"
            + commit
            + "/"
            + path
        )


    # ==============================================================
    # Release submission
    # ==============================================================

    @gl.public.write
    def submit_release(
        self,
        release_label: str,
        source_commit: str
    ) -> typing.Any:
        """
        Submit an immutable repository commit for compliance review.

        Only the registered maintainer may submit a release.

        The commit SHA is stored before the review begins so that all
        validators evaluate the same repository version.
        """

        self._require_maintainer()

        if self.current_status == "UNDER_REVIEW":
            raise gl.vm.UserError(
                "A compliance review is already in progress."
            )

        if not release_label.strip():
            raise gl.vm.UserError(
                "Release label cannot be empty."
            )

        if not source_commit.strip():
            raise gl.vm.UserError(
                "Source commit cannot be empty."
            )

        commit = source_commit.strip()

        if len(commit) < 7:
            raise gl.vm.UserError(
                "Source commit must contain a valid commit identifier."
            )

        self.current_release = release_label.strip()
        self.current_commit = commit

        self.current_status = "UNDER_REVIEW"
        self.has_resolved = False

        self.compliance_score = 0

        self.detected_license = ""
        self.license_risk = ""

        self.evidence_summary = (
            "Release submitted for source-grounded compliance review."
        )

        self.decision_summary = ""

        return {
            "status": self.current_status,
            "release": self.current_release,
            "commit": self.current_commit
        }


    # ==============================================================
    # Source retrieval and analysis
    # ==============================================================

    def _collect_and_analyze(
        self,
        repository: str,
        commit: str,
        policy: str,
        release: str
    ) -> typing.Any:
        """
        Retrieve pinned repository evidence and perform the
        non-deterministic compliance analysis.

        This function is intentionally self-contained so that
        validators can independently reproduce the evidence
        retrieval and reasoning process.
        """

        # ----------------------------------------------------------
        # License evidence
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

                    body = response.body.decode(
                        "utf-8"
                    )

                    if body.strip():

                        license_evidence.append(
                            "FILE: "
                            + path
                            + "\n"
                            + body[:12000]
                        )

            except Exception:
                pass


        # ----------------------------------------------------------
        # Supporting project metadata
        # ----------------------------------------------------------

        metadata_paths = [
            "README.md",
            "pyproject.toml",
            "package.json",
            "Cargo.toml",
            "go.mod"
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

                    body = response.body.decode(
                        "utf-8"
                    )

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
        # No license evidence
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


        license_text = (
            "\n\n--- LICENSE FILE ---\n"
            .join(license_evidence)
        )

        metadata_text = (
            "\n\n--- PROJECT METADATA ---\n"
            .join(metadata_evidence)
        )


        # ----------------------------------------------------------
        # Source-grounded AI analysis
        # ----------------------------------------------------------

        task = f"""
You are a decentralized open-source software compliance analyst.

Evaluate the exact software release represented by the pinned
GitHub commit below.

You MUST base the decision only on the retrieved repository
evidence.

Do not invent information.

Do not infer a license merely from the repository name.

Do not assume that a missing license file means a permissive
license.

Do not use information outside the supplied evidence.

If the evidence is insufficient or contradictory, return
HUMAN_REVIEW.

--------------------------------------------------
REPOSITORY
--------------------------------------------------

{repository}

--------------------------------------------------
RELEASE
--------------------------------------------------

{release}

--------------------------------------------------
PINNED COMMIT
--------------------------------------------------

{commit}

--------------------------------------------------
MAINTAINER LICENSE POLICY
--------------------------------------------------

{policy}

--------------------------------------------------
LICENSE EVIDENCE
--------------------------------------------------

{license_text}

--------------------------------------------------
PROJECT METADATA
--------------------------------------------------

{metadata_text}

--------------------------------------------------
DECISION RULES
--------------------------------------------------

COMPLIANT:

Return COMPLIANT only when the retrieved evidence clearly
identifies a license that satisfies the maintainer's policy.

NON_COMPLIANT:

Return NON_COMPLIANT only when the retrieved evidence clearly
identifies a license that violates the maintainer's policy.

HUMAN_REVIEW:

Return HUMAN_REVIEW when:

- license evidence is missing,
- license evidence is contradictory,
- license identity is unclear,
- the policy cannot be reliably applied,
- or the available evidence does not justify a confident decision.

--------------------------------------------------
SCORING
--------------------------------------------------

90-100:
Strong and clear compliance evidence.

70-89:
Likely compliant with minor uncertainty.

40-69:
Material uncertainty or mixed evidence.

1-39:
Strong evidence of non-compliance.

0:
Insufficient evidence or HUMAN_REVIEW.

--------------------------------------------------
OUTPUT
--------------------------------------------------

Return ONLY valid JSON.

Use exactly this structure:

{{
    "decision": "COMPLIANT",
    "score": 95,
    "risk": "LOW",
    "license": "MIT",
    "evidence_found": true,
    "summary": "The pinned repository evidence identifies MIT and it satisfies the configured policy."
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

The score must be an integer from 0 to 100.

The evidence_found field must be true or false.

Do not include markdown.

Do not include additional fields.

Do not provide explanations outside the JSON object.
"""

        try:

            raw_result = gl.nondet.exec_prompt(
                task
            )

            cleaned = (
                raw_result
                .replace("```json", "")
                .replace("```", "")
                .strip()
            )

            parsed = json.loads(
                cleaned
            )

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
        # Validate returned structure
        # ----------------------------------------------------------

        if not isinstance(
            parsed,
            dict
        ):

            return {
                "decision": "HUMAN_REVIEW",
                "score": 0,
                "risk": "UNKNOWN",
                "license": "UNDETERMINED",
                "evidence_found": False,
                "summary": "Invalid compliance analysis response."
            }


        decision = parsed.get(
            "decision"
        )

        score = parsed.get(
            "score"
        )

        risk = parsed.get(
            "risk"
        )

        license_name = parsed.get(
            "license"
        )

        evidence_found = parsed.get(
            "evidence_found"
        )

        summary = parsed.get(
            "summary"
        )


        # ----------------------------------------------------------
        # Normalize decision
        # ----------------------------------------------------------

        if decision not in [
            "COMPLIANT",
            "NON_COMPLIANT",
            "HUMAN_REVIEW"
        ]:

            decision = "HUMAN_REVIEW"


        # ----------------------------------------------------------
        # Normalize risk
        # ----------------------------------------------------------

        if risk not in [
            "LOW",
            "MEDIUM",
            "HIGH",
            "UNKNOWN"
        ]:

            risk = "UNKNOWN"


        # ----------------------------------------------------------
        # Normalize score
        # ----------------------------------------------------------

        if not isinstance(
            score,
            int
        ):

            score = 0

        if score < 0:
            score = 0

        if score > 100:
            score = 100


        # ----------------------------------------------------------
        # Normalize evidence flag
        # ----------------------------------------------------------

        if not isinstance(
            evidence_found,
            bool
        ):

            evidence_found = False


        # ----------------------------------------------------------
        # Normalize license
        # ----------------------------------------------------------

        if not isinstance(
            license_name,
            str
        ):

            license_name = "UNDETERMINED"


        # ----------------------------------------------------------
        # Normalize summary
        # ----------------------------------------------------------

        if not isinstance(
            summary,
            str
        ):

            summary = (
                "No reliable compliance summary available."
            )


        # ----------------------------------------------------------
        # Conservative evidence rule
        # ----------------------------------------------------------

        if not evidence_found:

            decision = "HUMAN_REVIEW"
            risk = "UNKNOWN"
            score = 0

        if license_name.strip() == "":

            decision = "HUMAN_REVIEW"
            risk = "UNKNOWN"
            score = 0

            license_name = "UNDETERMINED"


        return {
            "decision": decision,
            "score": score,
            "risk": risk,
            "license": license_name.strip(),
            "evidence_found": evidence_found,
            "summary": summary[:2000]
        }


    # ==============================================================
    # Review release
    # ==============================================================

    @gl.public.write
    def review_release(self) -> typing.Any:
        """
        Execute source-grounded compliance review.

        Only the registered maintainer may start the review.

        Each validator independently retrieves the same pinned
        repository evidence and evaluates it.

        GenLayer consensus requires substantive agreement on the
        compliance decision and evidence classification.
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


        # ----------------------------------------------------------
        # Leader evaluation
        # ----------------------------------------------------------

        def leader_evaluation() -> typing.Any:

            return self._collect_and_analyze(
                repository,
                commit,
                policy,
                release
            )


        # ----------------------------------------------------------
        # Validator verification
        # ----------------------------------------------------------

        def validator_fn(
            leader_result
        ) -> bool:
            """
            Validators independently execute the same evidence
            collection and analysis.

            They do not simply trust the leader's result.
            """

            if not isinstance(
                leader_result,
                gl.vm.Return
            ):
                return False

            try:

                leader_data = leader_result.calldata

                validator_data = (
                    self._collect_and_analyze(
                        repository,
                        commit,
                        policy,
                        release
                    )
                )

            except Exception:

                return False


            # ------------------------------------------------------
            # Validate decision
            # ------------------------------------------------------

            if (
                leader_data.get("decision")
                != validator_data.get("decision")
            ):

                return False


            # ------------------------------------------------------
            # Validate evidence availability
            # ------------------------------------------------------

            if (
                leader_data.get("evidence_found")
                != validator_data.get("evidence_found")
            ):

                return False


            # ------------------------------------------------------
            # Validate risk classification
            # ------------------------------------------------------

            if (
                leader_data.get("risk")
                != validator_data.get("risk")
            ):

                return False


            # ------------------------------------------------------
            # Validate normalized license identity
            # ------------------------------------------------------

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

            if (
                leader_license
                != validator_license
            ):

                return False


            # ------------------------------------------------------
            # Validate score within reasonable tolerance
            # ------------------------------------------------------

            try:

                leader_score = int(
                    leader_data.get(
                        "score",
                        0
                    )
                )

                validator_score = int(
                    validator_data.get(
                        "score",
                        0
                    )
                )

            except Exception:

                return False


            if abs(
                leader_score
                - validator_score
            ) > 10:

                return False


            return True


        # ----------------------------------------------------------
        # GenLayer non-deterministic consensus
        # ----------------------------------------------------------

        result = gl.vm.run_nondet_unsafe(
            leader_evaluation,
            validator_fn
        )


        # ----------------------------------------------------------
        # Read consensus result
        # ----------------------------------------------------------

        decision = result.get(
            "decision"
        )

        score = result.get(
            "score",
            0
        )

        risk = result.get(
            "risk",
            "UNKNOWN"
        )

        license_name = result.get(
            "license",
            "UNDETERMINED"
        )

        evidence_found = result.get(
            "evidence_found",
            False
        )

        summary = result.get(
            "summary",
            "No summary available."
        )


        # ----------------------------------------------------------
        # Defensive normalization
        # ----------------------------------------------------------

        if decision not in [
            "COMPLIANT",
            "NON_COMPLIANT",
            "HUMAN_REVIEW"
        ]:

            decision = "HUMAN_REVIEW"


        if not isinstance(
            score,
            int
        ):

            score = 0

        if score < 0:
            score = 0

        if score > 100:
            score = 100


        if risk not in [
            "LOW",
            "MEDIUM",
            "HIGH",
            "UNKNOWN"
        ]:

            risk = "UNKNOWN"


        if not isinstance(
            license_name,
            str
        ):

            license_name = "UNDETERMINED"


        if not isinstance(
            evidence_found,
            bool
        ):

            evidence_found = False


        if not isinstance(
            summary,
            str
        ):

            summary = "No reliable summary available."


        # ----------------------------------------------------------
        # Conservative final rule
        # ----------------------------------------------------------

        if not evidence_found:

            decision = "HUMAN_REVIEW"
            score = 0
            risk = "UNKNOWN"
            license_name = "UNDETERMINED"


        # ----------------------------------------------------------
        # Persist review evidence
        # ----------------------------------------------------------

        self.compliance_score = u32(
            score
        )

        self.detected_license = (
            license_name
        )

        self.license_risk = (
            risk
        )

        self.evidence_summary = (
            "Source-grounded review completed against pinned "
            "commit "
            + self.current_commit
            + ". Evidence available: "
            + str(evidence_found)
            + ". Detected license: "
            + license_name
            + "."
        )

        self.decision_summary = (
            summary
        )

        self.review_count = (
            self.review_count
            + u32(1)
        )

        self.last_reviewed_commit = (
            self.current_commit
        )


        # ----------------------------------------------------------
        # Deterministic state transition
        # ----------------------------------------------------------

        if decision == "COMPLIANT":

            self.current_status = (
                "COMPLIANT"
            )

            self.has_resolved = True


        elif decision == "NON_COMPLIANT":

            self.current_status = (
                "NON_COMPLIANT"
            )

            self.has_resolved = True


        else:

            self.current_status = (
                "HUMAN_REVIEW"
            )

            self.has_resolved = False


        return {
            "decision": decision,
            "score": score,
            "risk": risk,
            "license": license_name,
            "evidence_found": evidence_found,
            "summary": summary,
            "status": self.current_status,
            "release": self.current_release,
            "commit": self.current_commit
        }


    # ==============================================================
    # Reset / retry
    # ==============================================================

    @gl.public.write
    def reset_for_new_release(
        self
    ) -> typing.Any:
        """
        Safely reset a completed or disputed review.

        Only the maintainer can reset the lifecycle.

        A release currently UNDER_REVIEW cannot be reset.

        The repository, license policy and maintainer remain unchanged.
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
                "The registry is already ready for a new release."
            )


        self.current_status = (
            "READY_FOR_REVIEW"
        )

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
                "Compliance registry reset successfully. "
                "The maintainer can submit another pinned release."
            )
        }


    # ==============================================================
    # Public registry state
    # ==============================================================

    @gl.public.view
    def get_registry_state(
        self
    ) -> dict[str, typing.Any]:
        """
        Return the complete persistent registry state.
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


    # ==============================================================
    # Latest compliance result
    # ==============================================================

    @gl.public.view
    def get_compliance_result(
        self
    ) -> dict[str, typing.Any]:
        """
        Return the latest compliance result.
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
