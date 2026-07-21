# Master bibliography

The analysis prioritizes specifications and papers over secondary summaries.
Repository links in the subdocuments point directly to the implementation
surface under review.

<a id="baum26"></a>
## `[baum26]` PoMFRIT / blind signatures from MAYO

Carsten Baum, Marvin Beckmann, Ward Beullens, Shibam Mukherjee, and Christian
Rechberger. *Concretely Efficient Blind Signatures Based on VOLE-in-the-Head
Proofs and the MAYO Trapdoor*. USENIX Security 2026 prepublication;
Cryptology ePrint Archive, Paper 2026/109, 2026.

- [USENIX prepublication PDF](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_baum.pdf)
- [IACR ePrint landing page](https://eprint.iacr.org/2026/109)
- Used for Definition 3.1, Algorithms 1 and 2, Theorems 5.1 and 6.1, and
  Appendix A. Those labels were verified in the USENIX prepublication. The
  colleague's “Definition 8” may use alternate manuscript or publication
  numbering; the ePrint PDF itself was not independently fetched during this
  review, so the corpus uses the semantic game name when numbering matters.

<a id="mayo-r2"></a>
## `[mayo-r2]` MAYO Round-2 specification

Ward Beullens, Fabio Campos, Sofia Celi, Basil Hess, and Matthias J.
Kannwischer. *MAYO Specification Document, Round 2*. NIST Additional Digital
Signature Schemes project submission, 5 February 2025.

- [NIST-hosted PDF](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/mayo-spec-round2-web.pdf)
- [Project-hosted PDF](https://pqmayo.org/assets/specs/mayo-round2.pdf)
- Used for Algorithms 7 and 8, Definitions 1 and 2, Theorem 1, the Game
  3-to-Game 5 signer simulation, and the rejection bound in Section 5.3.

<a id="beullens22"></a>
## `[beullens22]` Original MAYO paper

Ward Beullens. *MAYO: Practical Post-Quantum Signatures from Oil-and-Vinegar
Maps*. Selected Areas in Cryptography 2021, LNCS 13203, pages 355-376,
Springer, 2022. [IACR ePrint 2021/1144](https://eprint.iacr.org/2021/1144)

Used to track older UOV/Whipped-MQ definition numbering and the evolution to
the Round-2 multi-target formulation.

<a id="bert08"></a>
## `[bert08]` Classical sponge indifferentiability

Guido Bertoni, Joan Daemen, Michael Peeters, and Gilles Van Assche. *On the
Indifferentiability of the Sponge Construction*. EUROCRYPT 2008.
[PDF](https://keccak.team/files/SpongeIndifferentiability.pdf)

Used only for the ideal-permutation sponge to random-oracle bridge; it does
not turn fixed Keccak-f[1600] into a programmable random oracle.

<a id="alagic25"></a>
## `[alagic25]` Quantum sponge indifferentiability

Gorjan Alagic, Joseph Carolan, Christian Majenz, and Saliha Tokat. *The Sponge
is Quantum Indifferentiable*. Cryptology ePrint Archive, Paper 2025/731, 2025.
[PDF](https://eprint.iacr.org/2025/731.pdf)

Used to distinguish quantum domain-extension results from the still-missing
QROM programming and extraction argument for VOLE-ACT.

<a id="coron00"></a>
## `[coron00]` Full-domain-hash reduction techniques

Jean-Sebastien Coron. *On the Exact Security of Full Domain Hash*. CRYPTO
2000. [PDF](https://cgi.di.uoa.gr/~aggelos/crypto/page4/assets/Coron-FDH.pdf)

Used as background for hash-query partitioning. RSA-specific algebraic tricks
must not be silently imported into the non-homomorphic MAYO relation.

<a id="fips202"></a>
## `[fips202]` SHA-3 and SHAKE standard

National Institute of Standards and Technology. *SHA-3 Standard:
Permutation-Based Hash and Extendable-Output Functions*. FIPS PUB 202, 2015.
[Official publication](https://doi.org/10.6028/NIST.FIPS.202)

Used for the concrete SHAKE/Keccak definition, not for any claim that SHAKE is
a programmable random oracle.
