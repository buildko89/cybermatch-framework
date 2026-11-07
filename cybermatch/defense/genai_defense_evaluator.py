"""Local heuristic screening; no proof of safety or media authenticity.

Fixed literal searches and bounded token patterns avoid nested repetition.
Context may mark untrusted documents with source=document/web/retrieval/email.
It never bypasses screening. Findings contain rule names, never secret values.
"""

import re
import unicodedata

from cybermatch.models.genai_defense import (
    GenAIEvaluationResult, GenAIRiskCategory as Category,
    GenAIRiskFinding, GenAISeverity as Severity,
)

PENALTIES = {Severity.CRITICAL: .4, Severity.HIGH: .25,
             Severity.MEDIUM: .1, Severity.LOW: 0.0}
DIRECT = (
    "ignore previous instructions", "ignore all previous instructions",
    "disregard previous instructions", "system override", "dan mode",
    "これまでの指示を無視", "以前の指示を無視", "前の指示を無視",
    "システム権限を取得", "制限を解除", "jailbreak",
)
INDIRECT = ("<system>", "<system ", "[prompt injection]", "hidden instruction",
            "隠し命令", "隠された指示", "<!--", 'display:none', 'display: none')
SECRET_PATTERNS = {
    "api_key": re.compile(r"(?<![a-zA-Z0-9])sk-(?:proj-|ant-api\d{2}-)?[a-zA-Z0-9_-]{20,}(?![a-zA-Z0-9_-])"),
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    "jwt": re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![\w-])"),
    "credential": re.compile(r"(?:password|passwd|api_key|api_secret|パスワード)\s{0,8}[:=：]\s{0,8}[^\s,;]{4,}", re.I),
    "credit_card": re.compile(r"(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])"),
    "my_number": re.compile(r"(?<![0-9])(?:[0-9]{12}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4})(?![0-9])"),
}
RULES = {
    Category.PROMPT_INJECTION_DIRECT: (
        Severity.HIGH, "LLM01: Prompt Injection", "AIへの指示の上書きが疑われます。",
        "AIが社内ルールを外れ、誤った判断や情報の持ち出しにつながるおそれがあります。",
        "入力とシステム指示を分離し、ツール権限を最小化して重要操作を人が承認してください。"),
    Category.PROMPT_INJECTION_INDIRECT: (
        Severity.HIGH, "LLM01: Prompt Injection", "参照資料中の命令や権限タグ偽装が疑われます。",
        "外部資料を読むだけでAIの処理が誘導され、情報漏洩や業務の誤処理につながるおそれがあります。",
        "外部資料を信頼しないデータとして扱い、命令として実行せず、外部通信を制限してください。"),
    Category.SENSITIVE_DATA_LEAKAGE: (
        Severity.HIGH, "LLM06: Sensitive Information Disclosure", "認証情報または個人情報の形式を検知しました。",
        "AIサービスへの機密情報送信により、不正アクセスや顧客信用の低下につながるおそれがあります。",
        "送信を停止し機密情報を除去してください。漏洩した認証情報は失効・再発行し、利用履歴を確認してください。"),
    Category.DEEPFAKE_BEC_ATTEMPT: (
        Severity.CRITICAL, "N/A: BEC social engineering", "役員なりすましによる緊急送金要求が疑われます。",
        "経営者の声や映像を信じた送金で、資金を失うおそれがあります。テキストだけでは映像・音声の真偽は判定できません。",
        "送金を保留し、登録済みの電話番号で本人に確認してください。口座変更を別経路で検証し、二者承認を徹底してください。"),
}


def _passes_luhn(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char in "0123456789"]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class GenAIDefenseEvaluator:
    def evaluate_input(self, text: str, context: dict | None = None) -> GenAIEvaluationResult:
        if not isinstance(text, str) or "\x00" in text:
            raise ValueError("text must be a string without null bytes")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in text):
            raise ValueError("text must not contain unpaired Unicode surrogates")
        if context is not None and not isinstance(context, dict):
            raise ValueError("context must be a dict or None")
        normalized = unicodedata.normalize("NFKC", text)
        lowered = normalized.casefold()
        instruction_text = re.sub(r"\s+", " ", "".join(
            char for char in lowered if unicodedata.category(char) != "Cf"))
        findings = []

        def report(category, pattern):
            severity, owasp, description, impact, guidance = RULES[category]
            findings.append(GenAIRiskFinding(category, severity, pattern,
                                            description, owasp, impact, guidance))

        direct = next((p for p in DIRECT if p in instruction_text), None)
        indirect = next((p for p in INDIRECT if p in instruction_text), None)
        source = (context or {}).get("source")
        untrusted = isinstance(source, str) and source.casefold() in (
            "document", "web", "retrieval", "email")
        if indirect or (direct and untrusted):
            report(Category.PROMPT_INJECTION_INDIRECT, "embedded_instruction")
        elif direct:
            report(Category.PROMPT_INJECTION_DIRECT, "instruction_override")
        for name, pattern in SECRET_PATTERNS.items():
            matched = (any(_passes_luhn(match.group()) for match in pattern.finditer(normalized))
                       if name == "credit_card" else pattern.search(normalized))
            if matched:
                report(Category.SENSITIVE_DATA_LEAKAGE, name)

        groups = (
            ("ceo", "cfo", "社長", "役員", "経営者", "取締役"),
            ("送金", "振込", "振り込", "transfer", "wire", "payment"),
            ("急ぎ", "至急", "緊急", "今すぐ", "urgent", "immediately"),
            ("極秘", "秘密", "内密", "口座変更", "口座を変更", "confidential", "secret", "new account", "change account"),
        )
        if all(any(token in lowered for token in group) for group in groups):
            report(Category.DEEPFAKE_BEC_ATTEMPT, "executive_urgent_confidential_payment")
        score = round(max(0.0, 1.0 - sum(PENALTIES[f.severity] for f in findings)), 10)
        safe = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        impacts = list(dict.fromkeys(f.business_impact for f in findings))
        summary = ("注意が必要な兆候を検知しました。処理を保留し、担当者が確認してください。"
                   + "".join(impacts) if findings else
                   "既知のリスク兆候は検知されませんでした。通常の情報管理と承認手続きを継続してください。")
        return GenAIEvaluationResult(tuple(findings), score, summary, safe)
