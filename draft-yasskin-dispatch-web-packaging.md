---
coding: utf-8

title: Web Packaging
abbrev: web-packaging
docname: draft-yasskin-dispatch-web-packaging-latest
date: 2017-06-15
category: std

ipr: trust200902
area: General
workgroup: Dispatch
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: J. Yasskin
    name: Jeffrey Yasskin
    organization: Google
    email: jyasskin@chromium.org


--- abstract

NAT (Network Address Translator) Traversal may require TURN
(Traversal Using Relays around NAT) functionality in certain
cases that are not unlikely to occur.  There is little
incentive to deploy TURN servers, except by those who need
them — who may not be in a position to deploy a new protocol
on an Internet-connected node, in particular not one with
deployment requirements as high as those of TURN.

"STUN/TURN using PHP in Despair" is a highly deployable
protocol for obtaining TURN-like functionality, while also
providing the most important function of STUN.

--- middle

Introduction        {#problems}
============

People would like to use content offline and in other situations where
there isn’t a direct connection to the server where the content
originates. However, it's difficult to distribute and verify the
authenticity of applications and content without a connection to the
network. The W3C has addressed running applications offline with
Service Workers ({{?service-workers-1}}), but not
the problem of distribution.

Use Cases    {#use-cases}
---------

### Offline Installation

People with expensive or intermittent internet connections are used
to sharing files via P2P links and shared SD cards. They should be
able to install web applications they received this way. Installing a
web application requires a TLS-type guarantee that it came from and
can use data owned by a particular origin.

### Snapshot packages

Verification of the origin of the content isn't always necessary.
For example, users currently share screenshots and MHTML documents
with their peers, with no guarantee that the shared content is
authentic. However, these formats have low fidelity (screenshots)
and/or aren't interoperable (MHTML). We'd like an interoperable format
that lets both publishers and readers package such content for use in
an untrusted mode.

### CDNs

CDNs want to re-publish other origins' content so readers can access
it more quickly or more privately. Currently, to attribute that
content to the original origin, they need the full ability to publish
arbitrary content under that origin's name. There should be a way to
let them attribute only the exact content that the original origin
published.

### ...

Why not ZIP?   {#not-zip}
------------

[WICG/webpackage#45](https://github.com/WICG/webpackage/issues/45)

The Need for Standardization   {#need}
----------------------------

Publishers and readers should be able to generate a package once, and have it
usable by all browsers.


Format   {#format}
======

Terminology          {#Terminology}
-----------

In this document, the key words "MUST", "MUST NOT", "REQUIRED",
"SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
and "OPTIONAL" are to be interpreted as described in BCP 14, RFC 2119
{{!RFC2119}} and indicate requirement levels for compliant Web Package
generators and parsers.


## Top-level structure

The package is a [CBOR-encoded data item](https://tools.ietf.org/html/rfc7049)
with MIME type `application/package+cbor`. It logically contains a flat sequence
of resources represented as HTTP responses. The package also includes metadata
such as a manifest and an index to let consumers validate the resources and
access them directly.

The overall structure of the item is described by the following
[CDDL](https://tools.ietf.org/html/draft-greevenbosch-appsawg-cbor-cddl):

~~~~~ cddl
webpackage = [
  magic1: h'F0 9F 8C 90 F0 9F 93 A6',  ; 🌐📦 in UTF-8.
  section-offsets: { * (($section-name .within tstr) => offset) },
  sections: ({ * $$section }) .within ({ * $section-name => any }),
  length: uint,                        ; Total number of bytes in the package.
  magic2: h'F0 9F 8C 90 F0 9F 93 A6',  ; 🌐📦 in UTF-8.
]

; Offsets are measured from the first byte of the webpackage item to the first
; byte of the target item.
offset = uint
~~~~~

Each section-offset points to a section with the same key, by holding the byte
offset from the start of the webpackage item to the start of the section's name
item.

The length holds the total length in bytes of the `webpackage` item and must be
encoded in the uint64_t format, which makes it possible to build self-extracting
executables by appending a normal web package to the extractor executable.

The defined section types are:

* [`"indexed-content"`](#main-content): The only required section.
  Maps resource keys (URLs possibly extended with HTTP headers) to
  HTTP2 responses. The mapping uses byte offsets to allow random
  access to any resource.
* [`"manifest"`](#manifest): Validates that resources came from the expected
  source. May refer to other manifests among the responses. If this section
  isn't provided, the resources are un-signed and can be loaded as untrusted
  data.

More sections may be defined later. If an unexpected section is encountered, it
is ignored.

Note that this top-level information is *not signed*, and so can't be trusted.
Only information in the manifest and below can be trusted.

## Main content

The main content of a package is an index of HTTP requests pointing to HTTP
responses. These request/response pairs hold the manifests of sub-packages and
the resources in the package and all of its sub-packages. Both the requests and
responses can appear in any order, usually chosen to optimize loading while the
package is streamed.

~~~~~ cddl
$section-name /= "indexed-content"
$$section //= ("indexed-content" => [
  index: [* [resource-key, offset, ? length: uint] ],
  responses: [* [response-headers: http-headers, body: bstr]],
])

resource-key = uri / http-headers

; http-headers is a byte string in HPACK format (RFC7541).
; The dynamic table begins empty for each instance of http-headers.
http-headers = bstr
~~~~~

A `uri` `resource-key` is equivalent to an `http-headers` block with ":method"
set to "GET" and with ":scheme", ":authority", and ":path" headers set from the
URI as described in
[RFC7540 section 8.1.2.3](https://tools.ietf.org/html/rfc7540#section-8.1.2.3).

As an optimization, the `resource-key`s in the index store relative instead of
absolute URLs. Each entry is resolved relative to the resolved version of the
previous entry.

TODO: Consider random access into large indices.

In addition to the CDDL constraints:

* All byte strings must use a definite-length encoding so that package consumers
  can parse the content directly instead of concatenating the indefinite-length
  chunks first. The definite lengths here may also help a package consumer to
  quickly send resources to other threads for parsing.
* The index must not contain two resolved `resource-key`s with the
  same [header list](http://httpwg.org/specs/rfc7541.html#rfc.section.1.3) after
  HPACK decoding.
* The `resource-key` must not contain any headers that aren't either ":method",
  ":scheme", ":authority", ":path", or listed in the
  `response-headers`'
  ["Vary" header](https://tools.ietf.org/html/rfc7231#section-7.1.4).
* The `resource-key` must contain at most one of each ":method", ":scheme",
  ":authority", ":path" header, in that order, before any other headers.
  Resolving the `resource-key` fills in any missing pseudo-headers from that
  set, ensuring that all resolved keys have exactly one of each.

The optional `length` field in the index entries is redundant with the length
prefixes on the `response-headers` and `body` in the content, but it can be used
to issue [Range requests](https://tools.ietf.org/html/rfc7233) for responses
that appear late in the `content`.


## Manifest

TODO: Now that this no longer contains
a [manifest](https://www.merriam-webster.com/dictionary/manifest#h3),
consider renaming it to something like "authenticity".

A package's manifest contains some metadata for the
package, [hashes](#validating-resources) for all resources included in that
package, and validity information for any [sub-packages](#sub-packages) the
package depends on. The manifest is signed, so that UAs can trust that it comes
from its claimed origin.

~~~~~ cddl
$section-name /= "manifest"
$$section //= ("manifest" => signed-manifest)

signed-manifest = {
  manifest: manifest,
  certificates: [+ certificate],
  signatures: [+ signature]
}

manifest = {
  metadata: manifest-metadata,
  resource-hashes: {* hash-algorithm => [hash-value]},
  ? subpackages: [* subpackage],
}

manifest-metadata = {
  date: time,
  origin: uri,
  * tstr => any,
}

; From https://www.w3.org/TR/CSP3/#grammardef-hash-algorithm.
hash-algorithm /= "sha256" / "sha384" / "sha512"
; Note that a hash value is not base64-encoded, unlike in CSP.
hash-value = bstr

; X.509 format; see https://tools.ietf.org/html/rfc5280
certificate = bstr

signature = {
  ; RFC5280 says certificates can be identified by either the
  ; issuer-name-and-serial-number or by the subject key identifier. However,
  ; issuer names are complicated, and the subject key identifier only identifies
  ; the public key, not the certificate, so we identify certificates by their
  ; index in the certificates array instead.
  keyIndex: uint,
  signature: bstr,
}
~~~~~

The metadata must include an absolute URL identifying
the
[origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin)
vouching for the package and the date the package was created. It may contain
more keys defined in https://www.w3.org/TR/appmanifest/.

### Manifest signatures

The manifest is signed by a set of certificates, including at least one that is
trusted to sign content from the
manifest's
[origin](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin).
Other certificates can sign to vouch for the package along other dimensions, for
example that it was checked for malicious behavior by some authority.

The signed sequence of bytes is the concatenation of the following byte strings.
This matches the TLS1.3 format to avoid cross-protocol attacks when TLS
certificates are used to sign manifests.
1. A string that consists of octet 32 (0x20) repeated 64 times.
1. A context string: the ASCII encoding of "Web Package Manifest".
1. A single 0 byte which serves as a separator.
1. The bytes of the `manifest` CBOR item.

Each signature uses the `keyIndex` field to identify the certificate used to
generate it. This certificate in turn identifies a signing algorithm in its
SubjectPublicKeyInfo. The signature does not separately encode the signing
algorithm to avoid letting attackers choose a weaker signature algorithm.

Further, the signing algorithm must be one of the SignatureScheme algorithms defined
by [TLS1.3](https://tlswg.github.io/tls13-spec/#rfc.section.4.2.3), except for
`rsa_pkcs1*` and the ones marked "SHOULD NOT be offered".

As a special case, if the package is being transferred from the manifest's
origin under TLS, the UA may load it without checking that its own resources match
the manifest. The UA still needs to validate resources provided by sub-manifests.


### Certificates

The `signed-manifest.certificates` array should contain enough
X.509 certificates to chain from the signing certificates, using the rules
in [RFC5280](https://tools.ietf.org/html/rfc5280), to roots trusted by all
expected consumers of the package.

[Sub-packages](#sub-packages') manifests can contain their own certificates or
can rely on certificates in their parent packages.

Requirements on the
certificates' [Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.3)
and [Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
are TBD. It may or may not be important to prevent TLS serving certificates from
being used to sign packages, in order to prevent cross-protocol attacks.


### Validating resources

For a resource to be valid, then for each `hash-algorithm => [hash-value]` in
`resource-hashes`, the resource's hash using that algorithm needs to appear in
that list of `hash-value`s. Like
in [Subresource Integrity](https://www.w3.org/TR/SRI/#agility), the UA will only
check one of these, but it's up to the UA which one.

The hash of a resource is the hash of its Canonical CBOR encoding using the
following CDDL. Headers are decompressed before being encoded and hashed.

~~~~~ cddl
resource = [
  request: [
    ':method', bstr,
    ':scheme', bstr,
    ':authority', bstr,
    ':path', bstr,
    * (header-name, header-value: bstr)
  ],
  response-headers: [
    ':status', bstr,
    * (header-name, header-value: bstr)
  ],
  response-body: bstr
]

# Headers must be lower-case ascii per
# http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2, and only
# pseudo-headers can include ":".
header-name = bstr .regexp "[\x21-\x39\x3b-\x40\x5b-\x7e]+"
~~~~~

This differs from [SRI](https://w3c.github.io/webappsec-subresource-integrity),
which only hashes the body. Note: This will usually prevent a package from
relying on some of its contents being transferred as normal network responses,
unless its author can guarantee the network won't change or reorder the headers.


### Sub-packages

A sub-package is represented by a [manifest](#manifest) file in
the [`"content"`](#main-content) section, which contains hashes of resources
from another origin. The sub-package's resources are not otherwise distinguished
from the rest of the resources in the package. Sub-packages can form an
arbitrarily-deep tree.

There are three possible forms of dependencies on sub-packages, of which we
allow two. Because a sub-package is protected by its
own [signature](#signatures), if the main package trusts the sub-package's
server, it could avoid specifying a version of the sub-package at all. However,
this opens the main package up to downgrade attacks, where the sub-package is
replaced by an older, vulnerable version, so we don't allow this option.

~~~~~ cddl
subpackage = [
  resource: resource-key,
  validation: {
    ? hash: hashes,
    ? notbefore: time,
  }
]
~~~~~

If the main package wants to load either the sub-package it was built with or
any upgrade, it can specify the date of the original sub-package:

~~~~~ cbor-diag
[32("https://example.com/loginsdk.package"), {"notbefore": 1(1486429554)}]
~~~~~

Constraining packages with their date makes it possible to link together
sub-packages with common dependencies, even if the sub-packages were built at
different times.

If the main package wants to be certain it's loading the exact version of a
sub-package that it was built with, it can constrain sub-package with a hash of its manifest:

~~~~~ cbor-diag
[32("https://example.com/loginsdk.package"),
 {"hash": {"sha256": 22(b64'9qg0NGDuhsjeGwrcbaxMKZAvfzAHJ2d8L7NkDzXhgHk=')}}]
~~~~~

Note that because the sub-package may include sub-sub-packages by date, the top
package may need to explicitly list those sub-sub-packages' hashes in order to
be completely constrained.


Implementation Notes
====================

A STuPiD server implementation SHOULD delete stored data some
time after it was stored. It is RECOMMENDED not to delete the
data before five minutes have elapsed after it was stored.
Different client protocols will have different reactions to
data that have been deleted prematurely and cannot be
retrieved by the notified peer; this may be as trivial as
packet loss or it may cause a reliable byte-stream to fail
({{impl}}).
(TODO: It may be useful to provide some hints in the storing
POST request.)

STuPiD clients should aggregate data in order to minimize the
number of requests to the STuPiD server per second.
The specific aggregation method chosen depends on the data
rate required (and the maximum chunk size), the latency
requirements, and the application semantics.

Clearly, it is up to the implementation to decide how the data
chunks are actually stored.  A sufficiently silly STuPiD server
implementation might for instance use a MySQL database.


Security Considerations
=======================

Signature validation is difficult.

Packages with a valid signature need to be invalidated when either
* the private key for any certificate in the signature's validation
  chain is leaked, or
* a vulnerability is discovered in the package's contents.

Because packages are intended to be used offline, it's impossible to
inject a revocation check into the critical path of using the package,
and even in online scenarios, such revocation checks don't actually
work [citation]. Instead, package consumers must check for a
sufficiently recent set of validation files, consisting of OCSP
responses {{!RFC6960}} and signed package version constraints, for
example within the last 7-30 days.

--- back


Examples  {#xmp}
========

This appendix provides some examples of web packages.

The packages are written in CBOR's extended diagnostic notation
({{?draft-greevenbosch-appsawg-cbor-cddl-10}}, Appendix G), with the
extensions that:
1. `hpack({key:value,...})` is an HPACK ({{?RFC7541}}) encoding of the
   described headers.
2. `DER(...)` is the DER encoding of a certificate described partially by the
   contents of the `...`.

All examples are available in the [examples](examples) directory.

## Single site: a couple of web pages with resources in a package.
The example web site contains two HTML pages and an image. This is straightforward case, demonstrating the following:

1. The `section-offsets` section declares one main section starting 1 byte into
   the `sections` item. (The 1 byte is the map header for the `sections` item.)
2. The `index` maps [hpack](http://httpwg.org/specs/rfc7541.html)-encoded
   headers for each resource to the start of that resource, measured relative to
   the start of the `responses` item.
3. Each resource contains `date`/`expires` headers that specify when the
   resource can be used by UA, similar to HTTP 1.1
   [Expiration Model](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.2).
   The actual expiration model is TBD and to be reflected in the spec. Note that
   we haven't yet described a way to set an `expires` value for the whole
   package at once.
4. The length of the whole package always appears from the 10th to 18th bytes
   before the end of the package, in big-endian format.

~~~~~ cbor-diag
['🌐📦',
    {"indexed-content": 1},
    {"indexed-content":
        [
            [ # Index.
                [hpack({
                    :method: GET,
                    :scheme: https
                    :authority: example.com
                    :path: /index.html
                }), 1],
                [hpack({
                    :method: GET
                    :scheme: https
                    :authority: example.com
                    :path: /otherPage.html
                }), 121],
                [hpack({
                    :method: GET
                    :scheme: https
                    :authority: example.com
                    :path: /images/world.png
                }), 243]
            ],
            [ # Resources.
                [
                    hpack({
                        :status: 200
                        content-type: text/html
                        date: Wed, 15 Nov 2016 06:25:24 GMT
                        expires: Thu, 01 Jan 2017 16:00:00 GMT
                    }),
                    '<body>\n  <a href=\"otherPage.html\">Other page</a>\n</body>\n'
                ],
                [
                    hpack({
                        :status: 200
                        content-type: text/html
                        date: Wed, 15 Nov 2016 06:25:24 GMT
                        expires: Thu, 01 Jan 2017 16:00:00 GMT
                    }),
                    '<body>\n  Hello World! <img src=\"images/world.png\">\n</body>\n'
                ], [
                    hpack({
                        :status: 200
                        content-type: image/png
                        date: Wed, 15 Nov 2016 06:25:24 GMT
                        expires: Thu, 01 Jan 2017 16:00:00 GMT
                    }),
                    '... binary png image ...'
                ]
            ]
        ]
    },
    473,  # Always 8 bytes long.
    '🌐📦'
]
~~~~~

## Multiple Origins: a web page with a resources from the other origin.

The example web site contains an HTML page and pulls a script from the
well-known location (different origin). Note that there's no need to distinguish
the resources from other origins vs the ones from the main origin. Since none of
them are signed, the browser won't treat any as
[same-origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin)
with their claimed origin.

~~~~~ cbor-diag
['🌐📦',
    {"indexed-content": 1},
    {"indexed-content":
        [
            [
                [hpack({
                    :method: GET
                    :scheme: https
                    :authority: example.com
                    :path: /index.html
                }), 1],
                [hpack({
                    :method: GET
                    :scheme: https
                    :authority: ajax.googleapis.com
                    :path: /ajax/libs/jquery/3.1.0/jquery.min.js
                }), 179]
            ],
            [
                [
                    hpack({
                        :status: 200
                        content-type: text/html
                        date: Wed, 15 Nov 2016 06:25:24 GMT
                        expires: Thu, 01 Jan 2017 16:00:00 GMT
                    }),
                    '<head>\n<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.1.0/jquery.min.js\"></script>\n<body>\n...\n</body>\n'
                ],
                [
                    hpack({
                        :status: 200
                        content-type: text/html
                        date: Wed, 15 Nov 2016 06:25:24 GMT
                        expires: Thu, 01 Jan 2017 16:00:00 GMT
                    }),
                    '... some JS code ...\n'
                ]
            ]
        ]
    },
    396,
    '🌐📦'
]
~~~~~

## Signed package, one origin.

The example contains example.com/index.html. The package is signed by the
example.com publisher, using the same private key that example.com uses for
HTTPS. The signed package ensures the verification of the origin even if the
package is stored in a local file or obtained via other insecure ways like HTTP,
or hosted on another origin's server.

Some interesting things to notice in this package:

1. The `"manifest"` map contains `"certificates"` and `"signatures"` arrays
   describing how the manifest is signed.
2. The signature identifies the first element of `"certificates"` as the signing
   certificate.
3. The elements of `"certificates"` are
   DER-encoded [X.509 certificates](https://tools.ietf.org/html/rfc5280).
   The [signing certificate](go/webpack/testdata/pki/example.com.cert) is
   trusted for `example.com`, and that certificate chains,
   using [other elements](go/webpack/testdata/pki/intermediate1.cert) of
   `"certificates"`, to
   a [trusted root certificate](go/webpack/testdata/pki/root1.cert). The chain
   is built and trusted in the same way as TLS chains during normal web
   browsing.
4. The signature algorithm is determined by the signing certificate's public key
   type, `prime256v1`, and isn't encoded separately in the signature block.
5. The manifest contains a `"resource-hashes"` block, which contains the hashes,
   using the SHA384 algorithm in this case, of all resources in the package.
   Unlike in
   [Subresource Integrity](https://w3c.github.io/webappsec-subresource-integrity/),
   the hashes include the request and response headers.
6. The inclusion of a certificate chain makes it possible to validate the
   package offline. Browsers detect revoked certificates and packages with known
   vulnerabilities by looking for separately signed files containing OCSP and
   recency information, but this package does not demonstrate how to attach
   those.

~~~~~ cbor-diag
[
  '🌐📦',
  {
    "manifest": 1,
    "indexed-content": 2057
  },
  {
    "manifest": {
      "manifest": {
        "metadata": {
          "date": 1(1494583200),
          "origin": 32("https://example.com")
        },
        "resource-hashes": {
          "sha384": [
            h'3C3A03F7C3FC99494F6AAA25C3D11DA3C0D7097ABBF5A9476FB64741A769984E8B6801E71BB085E25D7134287B99BAAB',
            h'5AA8B83EE331F5F7D1EF2DF9B5AFC8B3A36AEC953F2715CE33ECCECD58627664D53241759778A8DC27BCAAE20F542F9F',
            h'D5B2A3EA8FE401F214DA8E3794BE97DE9666BAF012A4B515B8B67C85AAB141F8349C4CD4EE788C2B7A6D66177BC68171'
          ]
        }
      },
      "signatures": [
        {
          "keyIndex": 0,
          "signature": h'3044022015B1C8D46E4C6588F73D9D894D05377F382C4BC56E7CDE41ACEC1D81BF1EBF7E02204B812DACD001E0FD4AF968CF28EC6152299483D6D14D5DBE23FC1284ABB7A359'
        }
      ],
      "certificates": [
        DER(
          Certificate:
              ...
              Signature Algorithm: ecdsa-with-SHA256
                  Issuer: C=US, O=Honest Achmed's, CN=Honest Achmed's Test Intermediate CA
                  Validity
                      Not Before: May 10 00:00:00 2017 GMT
                      Not After : May 18 00:10:36 2018 GMT
                  Subject: C=US, O=Test Example, CN=example.com
                  Subject Public Key Info:
                      Public Key Algorithm: id-ecPublicKey
                          Public-Key: (256 bit)
                          pub:
                              ...
                          ASN1 OID: prime256v1
                  ...
        ),
        DER(
          Certificate:
              ...
              Signature Algorithm: sha256WithRSAEncryption
                  Issuer: C=US, O=Honest Achmed's, CN=Honest Achmed's Test Root CA
                  Validity
                      Not Before: May 10 00:00:00 2017 GMT
                      Not After : May 18 00:10:36 2018 GMT
                  Subject: C=US, O=Honest Achmed's, CN=Honest Achmed's Test Intermediate CA
                  Subject Public Key Info:
                      Public Key Algorithm: id-ecPublicKey
                          Public-Key: (521 bit)
                          pub:
                              ...
                          ASN1 OID: secp521r1
                  ...
        )
      ]
    },
    "indexed-content": [
      [
        [ hpack({
            :method: GET
            :scheme: https
            :authority: example.com
            :path: /index.html
          }), 1]
        [ hpack({
            :method: GET
            :scheme: https
            :authority: example.com
            :path: /otherPage.html
          }), 121],
        [ hpack({
            :method: GET
            :scheme: https
            :authority: example.com
            :path: /images/world.png
          }), 243]
        ],
      ],
      [
        [ hpack({
            :status: 200
            content-type: text/html
            date: Wed, 15 Nov 2016 06:25:24 GMT
            expires: Thu, 01 Jan 2017 16:00:00 GMT
          }),
          '<body>\n  <a href=\"otherPage.html\">Other page</a>\n</body>\n'
        ]
        [ hpack({
            :status: 200
            content-type: text/html
            date: Wed, 15 Nov 2016 06:25:24 GMT
            expires: Thu, 01 Jan 2017 16:00:00 GMT
          }),
          '<body>\n  Hello World! <img src=\"images/world.png\">\n</body>\n'
        ],
        [ hpack({
            :status: 200
            content-type: image/png
            date: Wed, 15 Nov 2016 06:25:24 GMT
            expires: Thu, 01 Jan 2017 16:00:00 GMT
          }),
          '... binary png image ...'
        ]
      ]
    ]
  },
  2541,
  '🌐📦'
]
~~~~~

The process of validation:

1. Verify that certificates identified by signature elements chain to trusted roots.
2. Find the subset of the signatures that correctly sign the manifest's bytes
   using their identified certificates' public keys.
3. Parse the manifest and find its claimed origin.
4. Verify that at least one correct signature identifies a certificate that's
   trusted for use by that origin.
5. When loading a resource, pick the strongest hash function in the
   `"resource-hashes"` map, and use that to hash the Canonical CBOR
   representation of its request headers, response headers, and body. Verify
   that the resulting digest appears in that array in the `"resource-hashes"`
   map.
