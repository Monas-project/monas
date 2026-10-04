//! How concurrent versions of a content converge.
//!
//! A version's payload holds two things with different natures: the content
//! body (the newest write is the right answer — last-writer-wins) and the
//! access policy, whose one mutable field, `min_valid_issued_at`, only ever
//! moves forward (the most restrictive value is the right answer — a max).
//! crsl-lib's built-in merge is LWW over the *whole* payload, which treats the
//! policy as if it were part of the body. Two failures follow from that when
//! a revoke and a write happen concurrently — a member the revoke has not
//! reached yet accepts a write, a partition, or plain sync lag:
//!
//! - Write after revoke (by timestamp): the write's node carries the policy
//!   it inherited, i.e. the pre-revoke cutoff. LWW copies that node whole and
//!   the revoke is gone from the head — the revoked recipient can keep
//!   writing.
//! - Revoke after write: the revoke's node carries the body it inherited.
//!   LWW copies *that* whole, and a legitimate write that was never in
//!   conflict with anything is silently dropped.
//!
//! [`MonasMergePolicy`] merges field by field: the body carries the order of
//! its last explicit write (`body_updated_at`). Policy-only nodes and merge
//! nodes carry that order unchanged, so neither can hide a branch's write or
//! promote an old write using a fresh merge timestamp. Equal write orders use
//! the body bytes as a deterministic tie-break. `min_valid_issued_at` is the
//! max across all heads. Owner and content id are fixed at genesis.
//!
//! This decides what a merge node *contains*; it does not judge whether a
//! head should have been accepted. A write a stale member let through under
//! a since-voided token still wins the body if it is the newest write. Ruling
//! it out needs the write to carry its token so the merge can check it
//! against the merged cutoff — a wire-format change tracked separately.
//!
//! Every replica must run the same policy (crsl-lib installs it per process;
//! it does not travel with the data). Replicas merging the same heads under
//! different rules produce different merge nodes and re-merge until one
//! rule wins by timestamp — during which the cutoff can regress.

use crate::domain::access_policy::AccessPolicy;
use crsl_lib::convergence::policy::{MergePolicy, ResolveInput};

use super::crdt_repository::ContentPayload;

/// Field-wise merge: max body-write register and max invalidation policy.
/// Neither decision depends on the timestamp or parents of a merge node.
pub struct MonasMergePolicy;

impl MonasMergePolicy {
    fn body_winner(nodes: &[ResolveInput<ContentPayload>]) -> &ResolveInput<ContentPayload> {
        nodes
            .iter()
            .max_by(|a, b| {
                a.payload
                    .body_updated_at
                    .cmp(&b.payload.body_updated_at)
                    .then_with(|| a.payload.data.cmp(&b.payload.data))
            })
            .expect("MonasMergePolicy requires at least one candidate node")
    }

    /// Policies share immutable owner/content identity. Select the highest
    /// invalidation value independently of the body, retaining its metadata.
    fn merged_policy(nodes: &[ResolveInput<ContentPayload>]) -> Option<AccessPolicy> {
        nodes
            .iter()
            .filter_map(|n| n.payload.access_policy.as_ref())
            .max_by_key(|p| (p.min_valid_issued_at(), p.updated_at()))
            .cloned()
    }
}

impl MergePolicy<ContentPayload> for MonasMergePolicy {
    fn resolve(&self, nodes: &[ResolveInput<ContentPayload>]) -> ContentPayload {
        let winner = Self::body_winner(nodes);
        ContentPayload {
            data: winner.payload.data.clone(),
            body_updated_at: winner.payload.body_updated_at,
            access_policy: Self::merged_policy(nodes),
        }
    }

    fn name(&self) -> &str {
        "monas-fieldwise"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::identity::Identity;
    use crate::domain::value_objects::ContentId;
    use cid::Cid;
    use multihash_codetable::{Code, MultihashDigest};

    fn cid(label: &str) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(label.as_bytes()))
    }

    fn policy(cutoff: u64) -> AccessPolicy {
        let mut p = AccessPolicy::new(
            ContentId::new("content-1".to_string()).unwrap(),
            Identity::user("alice".to_string()).unwrap(),
        );
        p.raise_min_valid_issued_at(cutoff);
        p
    }

    fn payload(data: &str, cutoff: u64) -> ContentPayload {
        ContentPayload {
            data: data.as_bytes().to_vec(),
            body_updated_at: 0,
            access_policy: Some(policy(cutoff)),
        }
    }

    fn head(
        label: &str,
        data: &str,
        cutoff: u64,
        ts: u64,
        parent: Option<ContentPayload>,
    ) -> ResolveInput<ContentPayload> {
        let mut value = payload(data, cutoff);
        value.body_updated_at = parent
            .as_ref()
            .filter(|p| p.data == value.data)
            .map_or(ts, |p| p.body_updated_at);
        ResolveInput::with_parents(cid(label), value, ts, parent.into_iter().collect())
    }

    fn cutoff_of(p: &ContentPayload) -> u64 {
        p.access_policy.as_ref().unwrap().min_valid_issued_at()
    }

    /// The bug this policy exists for: a write accepted by a member that had
    /// not seen the revoke is newer than the revoke. Whole-payload LWW would
    /// copy the write's stale policy and drop the cutoff.
    #[test]
    fn write_after_revoke_keeps_the_cutoff() {
        let base = payload("AB", 0);
        let revoke = head("A", "AB", 1000, 10, Some(base.clone()));
        let write = head("B", "ABC", 0, 15, Some(base));

        let merged = MonasMergePolicy.resolve(&[revoke, write]);

        assert_eq!(merged.data, b"ABC"); // the write is newest, it wins the body
        assert_eq!(cutoff_of(&merged), 1000); // but the revoke survives
    }

    /// The other direction: the revoke is newer, but it did not write. The
    /// concurrent write must not be dropped by a node that only re-committed
    /// its parent's body.
    #[test]
    fn revoke_after_write_keeps_the_write() {
        let base = payload("AB", 0);
        let write = head("B", "ABC", 0, 10, Some(base.clone()));
        let revoke = head("A", "AB", 1000, 15, Some(base));

        let merged = MonasMergePolicy.resolve(&[write, revoke]);

        assert_eq!(merged.data, b"ABC");
        assert_eq!(cutoff_of(&merged), 1000);
    }

    /// Two real writes: plain LWW on the body, cutoff still max.
    #[test]
    fn two_writes_newest_body_wins() {
        let base = payload("AB", 500);
        let older = head("A", "ABX", 500, 10, Some(base.clone()));
        let newer = head("B", "ABY", 500, 15, Some(base));

        let merged = MonasMergePolicy.resolve(&[older, newer]);

        assert_eq!(merged.data, b"ABY");
        assert_eq!(cutoff_of(&merged), 500);
    }

    /// Two revokes with different cutoffs, no writes: the body is unchanged
    /// and the higher cutoff wins regardless of which node is newer.
    #[test]
    fn two_revokes_take_the_higher_cutoff() {
        let base = payload("AB", 0);
        let later_cutoff = head("A", "AB", 2000, 10, Some(base.clone()));
        let newer_node = head("B", "AB", 1000, 15, Some(base));

        let merged = MonasMergePolicy.resolve(&[later_cutoff, newer_node]);

        assert_eq!(merged.data, b"AB");
        assert_eq!(cutoff_of(&merged), 2000);
    }

    /// No parent information (ancestry not synced): a head is assumed to
    /// have written, so nothing is dropped.
    #[test]
    fn head_without_parents_counts_as_a_write() {
        let orphan = head("A", "ABC", 0, 10, None);
        let revoke = head("B", "AB", 1000, 15, Some(payload("AB", 0)));

        let merged = MonasMergePolicy.resolve(&[orphan, revoke]);

        assert_eq!(merged.data, b"ABC");
        assert_eq!(cutoff_of(&merged), 1000);
    }

    /// The result must not depend on head order (crsl-lib hands heads over in
    /// storage order, which differs per replica).
    #[test]
    fn resolve_is_order_independent() {
        let base = payload("AB", 0);
        let a = head("A", "AB", 1000, 10, Some(base.clone()));
        let b = head("B", "ABC", 0, 15, Some(base));

        let ab = MonasMergePolicy.resolve(&[a.clone(), b.clone()]);
        let ba = MonasMergePolicy.resolve(&[b, a]);

        assert_eq!(ab, ba);
    }

    #[test]
    fn write_register_is_associative_commutative_and_idempotent() {
        let a = head("a", "old", 300, 10, None);
        let b = head("b", "latest", 100, 30, None);
        let c = head("c", "middle", 200, 20, None);
        let expected = MonasMergePolicy.resolve(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(expected.data, b"latest");
        assert_eq!(expected.body_updated_at, 30);
        assert_eq!(cutoff_of(&expected), 300);
        for [x, y, z] in [
            [a.clone(), b.clone(), c.clone()],
            [a.clone(), c.clone(), b.clone()],
            [b.clone(), a.clone(), c.clone()],
            [b.clone(), c.clone(), a.clone()],
            [c.clone(), a.clone(), b.clone()],
            [c, b, a],
        ] {
            let xy = MonasMergePolicy.resolve(&[x.clone(), y.clone()]);
            // Deliberately much newer NODE timestamp, preserving BODY order.
            let merged = ResolveInput::with_parents(
                cid("merge"),
                xy.clone(),
                9999,
                vec![x.payload, y.payload],
            );
            assert_eq!(MonasMergePolicy.resolve(&[merged.clone(), z]), expected);
            assert_eq!(MonasMergePolicy.resolve(&[merged.clone(), merged]), xy);
        }
    }

    #[test]
    fn simultaneous_writes_use_body_bytes_not_head_order_or_node_time() {
        let a = head("a", "aaa", 100, 10, None);
        let mut b = head("b", "zzz", 200, 10, None);
        b.timestamp = 1; // it is body_updated_at, not this timestamp, that matters
        let ab = MonasMergePolicy.resolve(&[a.clone(), b.clone()]);
        let ba = MonasMergePolicy.resolve(&[b, a]);
        assert_eq!(ab, ba);
        assert_eq!(ab.data, b"zzz");
        assert_eq!(ab.body_updated_at, 10);
        assert_eq!(cutoff_of(&ab), 200);
    }

    #[test]
    fn ancestry_availability_does_not_change_the_body_winner() {
        let a = head("a", "new", 100, 30, None);
        let b = head("b", "old", 200, 20, None);
        let expected = MonasMergePolicy.resolve(&[a.clone(), b.clone()]);
        let mut with_parents = a;
        with_parents.parent_payloads = vec![with_parents.payload.clone(), b.payload.clone()];
        assert_eq!(
            MonasMergePolicy.resolve(&[with_parents.clone(), b.clone()]),
            expected
        );
        with_parents.parent_payloads.pop();
        assert_eq!(MonasMergePolicy.resolve(&[with_parents, b]), expected);
    }
}
