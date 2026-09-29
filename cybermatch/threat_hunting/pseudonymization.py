"""実ログadapterで利用するidentityのHMAC仮名化。"""

from __future__ import annotations

import hashlib
import hmac
import re


class IdentityPseudonymizationError(ValueError):
    """鍵、鍵version、またはidentity入力が仮名化条件を満たさない。"""


class HmacIdentityPseudonymizer:
    """平文identityをversion付きHMAC-SHA-256 referenceへ変換する。

    このinstanceは入力値を保持せず、鍵も公開propertyとして返さない。これは
    仮名化であり匿名化ではない。鍵の保管・rotation・破棄は呼出側の責務である。
    """

    _KEY_VERSION = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")

    def __init__(self, *, key: bytes | bytearray, key_version: str):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise IdentityPseudonymizationError("HMAC鍵は16 byte以上のbytesで指定してください")
        if not isinstance(key_version, str) or self._KEY_VERSION.fullmatch(key_version) is None:
            raise IdentityPseudonymizationError("key_versionは安全な32文字以内の識別子で指定してください")
        self._key = bytes(key)
        self._key_version = key_version

    @property
    def key_version(self) -> str:
        return self._key_version

    def identity_ref(self, identity: str) -> str:
        """平文を返さず、`key_version:hex_digest`形式のreferenceだけを返す。"""
        if not isinstance(identity, str) or not identity.strip() or identity != identity.strip():
            raise IdentityPseudonymizationError("identityは空でない前後空白なしの文字列で指定してください")
        digest = hmac.new(self._key, identity.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{self._key_version}:{digest}"


__all__ = ["HmacIdentityPseudonymizer", "IdentityPseudonymizationError"]
