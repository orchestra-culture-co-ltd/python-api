# # Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from future.utils import raise_from

import sys
import urllib
import pytz
import hashlib
import base64
import hmac


from datetime import datetime


if sys.version_info[0] > 2:
    from datetime import timezone
else:
    from pytz import timezone, utc
    timezone.utc = utc


def patch():
    # 1. Add more urllib function.
    from six import _importer, MovedAttribute, Module_six_moves_urllib_parse

    attr = MovedAttribute("splitport", "urllib", "urllib.parse")
    setattr(Module_six_moves_urllib_parse, attr.name, attr)
    Module_six_moves_urllib_parse._moved_attributes.append(attr)

    _importer._add_module(Module_six_moves_urllib_parse("six.moves.urllib_parse"),
                          "moves.urllib_parse", "moves.urllib.parse")

    if sys.version_info[0] > 2:
        pass
    else:
        pass


def _parse_iso8601_string(value):
    """turns ISO 8601 string into datetime object."""
    ISO8601_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f")

    value = value.rstrip("Z")

    # Python interpreter will raise "AttributeError: _strptime" in multiple thread.
    # Import _strptime explicitly will solve problem.
    import _strptime

    for format_str in ISO8601_FORMATS:
        try:
            parsed_value = datetime.strptime(value, format_str)
            break
        except ValueError:
            try:
                parsed_value = datetime.strptime(value[:-6], format_str)
                break
            except ValueError:
                pass
    else:
        raise ValueError("failed to hydrate the %s timestamp" % value)

    return parsed_value.replace(tzinfo=pytz.utc)


def _md5sum_hash(data):
    """Compute MD5 of data and return hash as Base64 encoded value."""
    if data is None:
        return None

    hasher = hashlib.md5()
    try:
        # DEBUG: UnicodeDecodeError: 'utf8' codec can't decode byte 0xd1 in position 27: invalid continuation byte.
        string = data.encode() if isinstance(data, str) else data
    except:
        string = data
    hasher.update(string)
    md5sum = base64.b64encode(hasher.digest())
    return md5sum.decode() if isinstance(md5sum, bytes) else md5sum


def _sha256_hash(data):
    """Compute SHA-256 of data and return hash as hex encoded value."""
    data = data or b""
    hasher = hashlib.sha256()
    try:
        # DEBUG: UnicodeDecodeError: 'utf8' codec can't decode byte 0xd1 in position 27: invalid continuation byte.
        string = data.encode() if isinstance(data, str) else data
    except:
        string = data
    hasher.update(string)
    sha256sum = hasher.hexdigest()
    return sha256sum.decode() if isinstance(sha256sum, bytes) else sha256sum


def _hmac_hash(key, data, hexdigest=False):
    """Return HMacSHA256 digest of given key and data."""

    hasher = hmac.new(key, data, hashlib.sha256)
    return hasher.hexdigest() if hexdigest else hasher.digest()


def _to_utc(value):
    """Convert to UTC time if value is not naive."""
    return (
        value.astimezone(timezone.utc).replace(tzinfo=None)
        if value.tzinfo else value
    )


def _to_signer_date(value):
    """Format datetime into SignatureV4 date formatted string."""
    return _to_utc(value).strftime("%Y%m%d")


def _to_amz_date(value):
    """Format datetime into AMZ date formatted string."""
    return _to_utc(value).strftime("%Y%m%dT%H%M%SZ")


def _guess_user_metadata(key):
    key = key.lower()
    return not (
        key.startswith("x-amz-") or
        key in [
            "cache-control",
            "content-encoding",
            "content-type",
            "content-disposition",
            "content-language",
        ]
    )


def _normalize_headers(headers):
    """Normalize headers by prefixing 'X-Amz-Meta-' for user metadata."""
    # headers = {str(key): value for key, value in (headers or {}).items()}
    headers = {}
    for key, value in (headers or {}).items():
        headers[str(key)] = value

    # user_metadata = {
    #     key: value for key, value in headers.items()
    #     if _guess_user_metadata(key)
    # }
    user_metadata = {}
    for key, value in headers.items():
        if _guess_user_metadata(key):
            user_metadata[key] = value

    # Remove guessed user metadata.
    _ = [headers.pop(key) for key in user_metadata]

    user_headers = _metadata_to_headers(user_metadata)
    headers.update(user_headers)
    return headers


def _generate_headers(headers, sse, tags, retention, legal_hold):
    """Generate headers for given parameters."""
    headers = _normalize_headers(headers)
    headers.update(sse.headers() if sse else {})
    tagging = "&".join(
        [
            _queryencode(key) + "=" + _queryencode(value)
            for key, value in (tags or {}).items()
        ],
    )
    if tagging:
        headers["x-amz-tagging"] = tagging
    if retention and retention.mode:
        headers["x-amz-object-lock-mode"] = retention.mode
        headers["x-amz-object-lock-retain-until-date"] = (
            _to_iso8601utc(retention.retain_until_date)
        )
    if legal_hold:
        headers["x-amz-object-lock-legal-hold"] = "ON"
    return headers


def _to_iso8601utc(value):
    """Format datetime into UTC ISO-8601 formatted string."""
    if value is None:
        return None

    value = _to_utc(value)
    return (
        value.strftime("%Y-%m-%dT%H:%M:%S.") + value.strftime("%f")[:3] + "Z"
    )


def _normalize_key(key):
    if not key.lower().startswith("x-amz-meta-"):
        key = "X-Amz-Meta-" + key
    return key


def _to_string(value):
    value = str(value)
    try:
        value.encode("us-ascii")
    except UnicodeEncodeError as exc:
        # raise ValueError(
        #     f"unsupported metadata value {value}; "
        #     f"only US-ASCII encoded characters are supported"
        # ) from exc
        raise_from(ValueError(
            "unsupported metadata value %s; only US-ASCII encoded characters are supported" % value), exc)
    return value


def _normalize_value(values):
    if not isinstance(values, (list, tuple)):
        values = [values]
    return [_to_string(value) for value in values]


def _metadata_to_headers(metadata):
    """Convert user metadata to headers."""

    # return {
    #     _normalize_key(key): _normalize_value(value)
    #     for key, value in (metadata or {}).items()
    # }
    _ = {}
    for key, value in (metadata or {}).items():
        _[_normalize_key(key)] = _normalize_value(value)
    return _


def _quote(resource, safe='/', encoding=None, errors=None):
    """
    Wrapper to urllib.parse.quote() replacing back to '~' for older python
    versions.
    """
    return urllib.parse.quote(
        resource,
        safe=safe,
        encoding=encoding,
        errors=errors,
    ).replace("%7E", "~")


def _queryencode(query, safe='', encoding=None, errors=None):
    """Encode query parameter value."""
    return _quote(query, safe, encoding, errors)
