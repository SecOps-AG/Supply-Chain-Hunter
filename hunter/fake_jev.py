"""Offline keyword stand-in for the Jev client, used by `hunter eval` and the tests. It never calls the network."""

from __future__ import annotations

from hunter.jev import ChoiceView, JevResult, JevUnavailable, NoulView, ScoreView
from hunter.standin import noul_for
from hunter.taxonomy import FAMILY_CRITERIA


def _normalize(weights: dict[str, float]) -> dict[str, float]:
    total = sum(weights.values()) or 1.0
    return {key: value / total for key, value in weights.items()}


def _choice(name: str, probabilities: dict[str, float]) -> ChoiceView:
    winner = max(probabilities, key=probabilities.get)
    return ChoiceView(choice=winner, probabilities=probabilities, confidence=0.8)


class KeywordJev:
    """Maps excerpt keywords to Nouls. Choice fan-out follows the same excerpt."""

    model = "jev-1.13.0"

    def __init__(self):
        self.calls: list[dict] = []

    def system_one(self, state: dict, questions: dict) -> JevResult:
        self.calls.append({"state": state, "questions": questions})
        excerpt = state.get("diff_excerpt") or ""
        lowered = excerpt.lower()
        nouls: dict[str, NoulView] = {}
        choices: dict[str, ChoiceView] = {}
        scores: dict[str, ScoreView] = {}
        for key, question in questions.items():
            kind = question["type"]
            if kind == "noul":
                nouls[key] = NoulView(noul=noul_for(key, excerpt))
            elif kind == "choice":
                choices[key] = self._choice_for(key, lowered, question)
            elif kind == "score":
                scores[key] = self._score_for(key, lowered, question)
        return JevResult(model=self.model, nouls=nouls, choices=choices, scores=scores)

    def _choice_for(self, key: str, excerpt: str, question: dict) -> ChoiceView:
        options = list(question["criteria"])
        if key == "attack_family":
            if "postinstall" in excerpt or "cmdclass" in excerpt or "base64" in excerpt:
                weights = {
                    "none": 0.02,
                    "obfuscated_loader": 0.06,
                    "install_hook": 0.50,
                    "dependency_abuse": 0.04,
                    "credential_theft": 0.22,
                    "persistence": 0.03,
                    "remote_payload": 0.08,
                    "wormlike_spread": 0.02,
                    "other": 0.03,
                }
            else:
                weights = {name: 0.02 for name in FAMILY_CRITERIA}
                weights["none"] = 0.84
            return _choice(key, _normalize(weights))
        if key == "suspected_cause":
            if "postinstall" in excerpt or "cmdclass" in excerpt:
                winner = "poisoned_install_script"
            elif "palette-telemetry" in excerpt:
                winner = "malicious_new_dependency"
            else:
                winner = "unknown"
            weights = {name: 0.05 for name in options}
            weights[winner] = 0.8
            return _choice(key, _normalize(weights))
        if key.startswith("subtype_"):
            family = key.split("_", 1)[1]
            # subtype ids are subtype_<family>, and family may contain underscores.
            family = key[len("subtype_") :]
            winner = options[0]
            if family == "install_hook":
                if "cmdclass" in excerpt:
                    winner = "setup_cmdclass"
                elif "postinstall" in excerpt or "preinstall" in excerpt:
                    winner = "lifecycle_script"
            elif family == "credential_theft":
                if "id_rsa" in excerpt or ".ssh" in excerpt:
                    winner = "ssh_material"
                elif "aws_" in excerpt:
                    winner = "cloud_keys"
                else:
                    winner = "env_tokens"
            elif family == "remote_payload" and "203.0.113." in excerpt:
                winner = "raw_ip_callback"
            weights = {name: 0.05 for name in options}
            weights[winner] = 0.8
            return _choice(key, _normalize(weights))
        weights = {name: 1.0 / len(options) for name in options}
        return _choice(key, weights)

    def _score_for(self, key: str, excerpt: str, question: dict) -> ScoreView:
        criteria = list(question["criteria"])
        index = 1
        if key == "blast_radius" and ("http://" in excerpt or "npm_token" in excerpt):
            index = 2
        if key == "data_collection" and "npm_token" in excerpt:
            index = 3
        weights = {str(i): 0.05 for i in range(len(criteria))}
        weights[str(index)] = 0.85
        probabilities = _normalize(weights)
        return ScoreView(
            score=float(index),
            probabilities=probabilities,
            confidence=0.75,
            legend={str(i): str(criteria[i]) for i in range(len(criteria))},
        )


class ScriptedJev:
    """Fixed family probabilities so routing tests do not depend on excerpt wording."""

    model = "jev-1.13.0"

    def __init__(self, family_probabilities: dict[str, float], noul: float = 0.9, reviewer: float = 0.04):
        self.family_probabilities = family_probabilities
        self.noul = noul
        self.reviewer = reviewer
        self.calls: list[dict] = []

    def system_one(self, state: dict, questions: dict) -> JevResult:
        self.calls.append(questions)
        nouls = {}
        choices = {}
        scores = {}
        for key, question in questions.items():
            kind = question["type"]
            if kind == "noul":
                value = self.reviewer if key == "reviewer_instructions" else self.noul
                nouls[key] = NoulView(noul=value)
            elif kind == "choice" and key == "attack_family":
                choices[key] = _choice(key, self.family_probabilities)
            elif kind == "choice":
                options = list(question["criteria"])
                winner = options[0]
                weights = {name: 0.02 for name in options}
                weights[winner] = 0.9
                choices[key] = _choice(key, _normalize(weights))
            elif kind == "score":
                criteria = list(question["criteria"])
                weights = {str(i): 0.05 for i in range(len(criteria))}
                weights["1"] = 0.85
                scores[key] = ScoreView(
                    score=1.0,
                    probabilities=_normalize(weights),
                    confidence=0.7,
                    legend={str(i): str(criteria[i]) for i in range(len(criteria))},
                )
        return JevResult(model=self.model, nouls=nouls, choices=choices, scores=scores)


class RaisingJev:
    model = "jev-1.13.0"

    def system_one(self, state: dict, questions: dict) -> JevResult:
        raise JevUnavailable("Jev is down")


class SliceFlipJev(KeywordJev):
    """Answers 0.02 on a manifests or code_hunks slice. Classify no longer asks those slices."""

    def system_one(self, state: dict, questions: dict) -> JevResult:
        result = super().system_one(state, questions)
        if state.get("slice") in {"code_hunks", "manifests"}:
            result.nouls = {key: NoulView(noul=0.02) for key in result.nouls}
        return result
