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
//! [`MonasMergePolicy`] merges field by field instead: the body is LWW among
//! the heads that actually changed it against their parent (a head that only
//! re-committed its parent's body did not write and must not win a write
//! race), and `min_valid_issued_at` is the max across all heads. Owner and
//! content id are fixed at genesis and simply carried.
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

/// Field-wise merge for [`ContentPayload`]: body is LWW among heads that
/// changed it, `min_valid_issued_at` is the max, the rest is carried.
pub struct MonasMergePolicy;

impl MonasMergePolicy {
    /// Did this head change the body against its parent(s)?
    ///
    /// A head with no parent payloads (a genesis, or ancestry the replica
    /// has not synced) is taken as a change: there is nothing to say it
    /// isn't, and the alternative — dropping it from the race — could lose a
    /// real write.
    fn changed_body(input: &ResolveInput<ContentPayload>) -> bool {
        input.parent_payloads.is_empty()
            || input
                .parent_payloads
                .iter()
                .any(|parent| parent.data != input.payload.data)
    }

    /// The head whose body should win: newest among those that wrote.
    fn body_winner(nodes: &[ResolveInput<ContentPayload>]) -> &ResolveInput<ContentPayload> {
        let mut writers = nodes.iter().filter(|n| Self::changed_body(n)).peekable();
        if writers.peek().is_some() {
            writers
                .max_by_key(|n| n.timestamp)
                .expect("peeked non-empty")
        } else {
            // Nobody changed the body: every head carries the same one, so
            // any head's copy is right. Newest, for determinism.
            nodes
                .iter()
                .max_by_key(|n| n.timestamp)
                .expect("MonasMergePolicy requires at least one candidate node")
        }
    }

    /// The policy to carry: the winner's, with the cutoff raised to the max
    /// seen on any head. A head without a policy (legacy content) contributes
    /// nothing.
    fn merged_policy(
        nodes: &[ResolveInput<ContentPayload>],
        base: Option<&AccessPolicy>,
    ) -> Option<AccessPolicy> {
        let base = base.or_else(|| nodes.iter().find_map(|n| n.payload.access_policy.as_ref()))?;
        let max_cutoff = nodes
            .iter()
            .filter_map(|n| n.payload.access_policy.as_ref())
            .map(AccessPolicy::min_valid_issued_at)
            .max()
            .unwrap_or(0);
        let mut merged = base.clone();
        merged.raise_min_valid_issued_at(max_cutoff);
        Some(merged)
    }
}

impl MergePolicy<ContentPayload> for MonasMergePolicy {
    fn resolve(&self, nodes: &[ResolveInput<ContentPayload>]) -> ContentPayload {
        let winner = Self::body_winner(nodes);
        ContentPayload {
            data: winner.payload.data.clone(),
            access_policy: Self::merged_policy(nodes, winner.payload.access_policy.as_ref()),
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
        ResolveInput::with_parents(
            cid(label),
            payload(data, cutoff),
            ts,
            parent.into_iter().collect(),
        )
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
}
