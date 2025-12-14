"""
Custom Sigma modifiers for OpenSearch PPL backend.

This module provides additional encoding modifiers that are not included
in the standard pySigma library, specifically UTF-16 encoding variants.
"""

from sigma.modifiers import (
    SigmaValueModifier,
    SigmaString,
    SigmaStringPartType,
    SigmaValueError,
    modifier_mapping,
)


class SigmaUTF16Modifier(SigmaValueModifier[SigmaString, SigmaString]):
    """
    Encode string as UTF-16LE (same as 'wide' modifier).
    
    This modifier provides an alias for the 'wide' modifier using the more
    descriptive name 'utf16'. It encodes strings using UTF-16 Little Endian.
    """

    def modify(self, val: SigmaString) -> SigmaString:
        r: list[SigmaStringPartType] = list()
        for item in val.s:
            if isinstance(
                item, str
            ):  # encode to utf-16le and decode as utf-8 to get null bytes between chars
                try:
                    r.append(item.encode("utf-16le").decode("utf-8"))
                except UnicodeDecodeError:  # this method only works for ascii characters
                    raise SigmaValueError(
                        f"UTF-16 modifier only allowed for ascii strings, input string '{str(val)}' isn't one",
                        source=self.source,
                    )
            else:  # just append special characters without further handling
                r.append(item)

        s = SigmaString()
        s.s = r
        return s


class SigmaUTF16LEModifier(SigmaValueModifier[SigmaString, SigmaString]):
    """
    Encode string as UTF-16LE (UTF-16 Little Endian).
    
    This is identical to the 'wide' and 'utf16' modifiers but provides
    an explicit name for Little Endian encoding.
    """

    def modify(self, val: SigmaString) -> SigmaString:
        r: list[SigmaStringPartType] = list()
        for item in val.s:
            if isinstance(
                item, str
            ):  # encode to utf-16le and decode as utf-8 to get null bytes between chars
                try:
                    r.append(item.encode("utf-16le").decode("utf-8"))
                except UnicodeDecodeError:  # this method only works for ascii characters
                    raise SigmaValueError(
                        f"UTF-16LE modifier only allowed for ascii strings, input string '{str(val)}' isn't one",
                        source=self.source,
                    )
            else:  # just append special characters without further handling
                r.append(item)

        s = SigmaString()
        s.s = r
        return s


class SigmaUTF16BEModifier(SigmaValueModifier[SigmaString, SigmaString]):
    """
    Encode string as UTF-16BE (UTF-16 Big Endian).
    
    This modifier encodes strings using UTF-16 Big Endian, placing the null
    byte before each character instead of after (as in UTF-16LE).
    """

    def modify(self, val: SigmaString) -> SigmaString:
        r: list[SigmaStringPartType] = list()
        for item in val.s:
            if isinstance(
                item, str
            ):  # encode to utf-16be - we need to handle this differently than LE
                try:
                    # Encode to UTF-16BE and decode as latin-1 to preserve byte values
                    # UTF-16BE puts the null byte before each character
                    encoded = item.encode("utf-16be")
                    # Decode as latin-1 (which is byte-to-byte compatible with the first 256 unicode chars)
                    r.append(encoded.decode("latin-1"))
                except (UnicodeDecodeError, UnicodeEncodeError):
                    raise SigmaValueError(
                        f"UTF-16BE modifier only allowed for ascii strings, input string '{str(val)}' isn't one",
                        source=self.source,
                    )
            else:  # just append special characters without further handling
                r.append(item)

        s = SigmaString()
        s.s = r
        return s


def register_custom_modifiers():
    """
    Register custom modifiers in the global modifier_mapping.
    
    This function should be called before parsing Sigma rules that use
    these custom modifiers.
    """
    modifier_mapping["utf16"] = SigmaUTF16Modifier
    modifier_mapping["utf16le"] = SigmaUTF16LEModifier
    modifier_mapping["utf16be"] = SigmaUTF16BEModifier
