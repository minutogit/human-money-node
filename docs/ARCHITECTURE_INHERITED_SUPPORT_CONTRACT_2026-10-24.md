# R02 inherited-support contract worksheet

Scope: F02 / R02; Z03, Z04, Z06, Z07; G3 and E05. Design was shared with the parent reviewer before production edits. R03 distributed coverage is explicitly not implemented here.

## Accepted premise and meaning

Admission uses the receiving node's existing authenticated, current, ordered committee and its unchanged `required_quorum(total)` rule. Recovering self cannot witness its own cut, and rank21 cannot replace absent witnesses. The relevant current region must satisfy its assumed honest-quorum bound: a qualified admission quorum cannot all falsely attest to previously admitted exclusions. This is the same conditional regional authority premise as cold state admission, not mathematical proof of a source's honesty. The fixed at-most-six fault bound applies to20-member committees; an island requires the analogous honest-quorum premise for its adaptive threshold. A signature authenticates a current source's assertion, not an independent proof that the assertion is true. An eclipsed or wholly dishonest qualified region remains outside that premise.

A source-reported integer alone is insufficient. A source derives admissible HMC class only from its committed exact `ConfirmationSupport`; native class comes from a new, separate `native_confirmation_support` table. A raw native `LockStatus::Final`, including the legacy one-signature representation, is not provenance. Missing provenance is committed as unknown/class0. Legacy local exclusions remain conservatively protected by existing ordering/omission checks; they cannot become exportable class2 facts merely because their local row says FINAL.

The receiver independently verifies a current qualified quorum of signatures committing to **both** the objective state and support metadata. It checks the streamed stage against both commitments. The current island quorum witnesses inherited class2; it does not mint new14-of20 original approvals or make the island capable of FINAL checkout. Original choice storage, live-proof purposes and checkout thresholds remain unchanged. No original signer archive or recursively transported certificate is retained.

## Exact bindings

The canonical length-prefixed domain `HUMOCO_V1_INHERITED_SUPPORT_CUT` binds frozen-reply version2, network, shard, current source identity, authenticated receiver identity, fresh source lease token, objective digest, separate support digest, and the fixed25000ms lease. Freshness also depends on the authenticated immediate request/reply, absolute nonrenewable source lease and daemon deadline/committee rechecks. Source readiness and signing health are existing cold-boundary prerequisites. This is not a portable checkout receipt.

Support-state commitment has its own length-prefixed domain `HUMOCO_V1_INHERITED_SUPPORT_STATE`, encoding version1 and shard. It streams native rows in parent order, then HMC rows in tag order. Each live row commits kind, bounded key length/key, collision parent, exact child, root identity (HMC root transaction id; zero for native), immutable root expiry and admitted class. Exact HMC root/state identity remains covered by signed root and staged root validation. Native root lifetime is its existing native storage contract. No support hash is substituted for the objective active-state digest.

HMC and native support live in disjoint tables and wire kind namespaces even for legacy arbitrary HMC tag strings. Entries must exactly match active child/parent/root expiry and class1or2. Unknown rows are class0 in the support commitment; the independently qualified current cut may still establish the existing current class1or2 upon installation.

## Existence versus completeness; R03 boundary

This patch deliberately retains full-cut objective equality and additionally requires full support-commitment equality among current witnesses. An agreeing quorum witnesses existence and the source's inherited admission context. The preexisting frozen full-cut/no-gap mechanism supplies its existing completeness premise; this patch does not solve distributed compatible facts with no identical whole-state/support quorum. Mixed known/unknown or contradictory support commitments do not agree and can leave a recipient unready. They are not averaged, promoted from one source or silently downgraded. The separate R03 worksheet and acceptance remain required.

## Installation, migration and lifecycle

Bounded snapshot pages carry compact support facts beside roots/locks. Active response version3 explicitly changes this encoding; frozen response version2 adds the signed commitment. Older cold peers fail availability checks conservatively; no unsigned fallback admits inherited support. No L1, SST, canonical voucher bytes, HRW encoding, original approval digest or Proto/Core/App DTO changes occur.

A non-public `VerifiedInheritedCut` is constructed by independently checking distinct source signatures, unchanged quorum, receiver membership and both commitments. The disk installer validates that capability against the stage before the one Immediate redb transaction. Roots, locks, support, quarantine and indexes share that transaction. Incoming effective per-row class participates in replacement ordering before mutation. Native fact creation uses verified current/inherited/prior support, never a preserved raw status. Existing RAM publication and readiness happen only after durable commit.

The new native table starts empty on migration; it never retrospectively certifies legacy FINAL rows. Such exclusions remain locally protected conservatively. Backup copies the new table from the same source read transaction. Both native expiry paths remove matching support at rootTTL+30s; HMC retains existing root-bound cleanup. Physical crash scheduling, lease exhaustion and distributed coverage remain broader R07/R03 obligations, not newly claimed from happy-path tests.
