//! Out-of-memory victim selection.
//!
//! When an allocation fails and nothing can be reclaimed, something has to
//! die. This module only chooses: the caller describes what could be killed
//! as [`Candidate`]s (a process, a guest, a cgroup, whatever it counts
//! resident pages for) and gets back a [`Choice`]. Signalling the victim,
//! waiting for it and logging are the caller's.
//!
//! A candidate's score is its resident pages plus its adjustment, in
//! thousandths of all memory ([`ADJ_MIN`] to [`ADJ_MAX`]). A candidate at
//! [`ADJ_MIN`] is exempt. One already on its way out is waited for rather
//! than another killed.

/// An adjustment that exempts a candidate from selection.
pub const ADJ_MIN: i32 = -1000;
/// The largest adjustment: a score of all memory added.
pub const ADJ_MAX: i32 = 1000;

/// Something that could be killed to free memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate<Id> {
    /// What the caller calls it by, returned in the [`Choice`].
    pub id: Id,
    /// Pages it holds that killing it would free.
    pub resident: u64,
    /// Its adjustment, from [`ADJ_MIN`] to [`ADJ_MAX`] (values outside are
    /// clamped).
    pub adj: i32,
    /// Never chosen whatever its score (an init process, a zombie, one with
    /// nothing resident to free).
    pub protected: bool,
    /// Already being killed or exiting.
    pub dying: bool,
}

/// The outcome of [`select`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice<Id> {
    /// Kill this one.
    Kill(Id),
    /// This one is already dying: let it finish and try again.
    Wait(Id),
    /// Nothing may be killed.
    Nothing,
}

/// Free pages below which a failed allocation counts as out of memory
/// rather than a transient failure.
pub const LOW_PAGES: u64 = 256;

/// Whether `free` pages is short enough that a failed allocation is for
/// want of memory.
pub fn is_low(free: u64) -> bool {
    free < LOW_PAGES
}

/// The adjustment clamped to its range.
fn clamp_adj(adj: i32) -> i64 {
    adj.clamp(ADJ_MIN, ADJ_MAX) as i64
}

/// A candidate's score in pages: resident pages plus the adjustment's share
/// of `total` pages. Negative for a large negative adjustment.
pub fn points(resident: u64, adj: i32, total: u64) -> i64 {
    let resident = i64::try_from(resident).unwrap_or(i64::MAX);
    let total = i64::try_from(total).unwrap_or(i64::MAX);
    resident.saturating_add(clamp_adj(adj).saturating_mul(total) / 1000)
}

/// The badness a selection would see, scaled to 0 to 2000 against all
/// memory (0 for an exempt candidate, at least 1 otherwise), as a
/// `/proc`-style score file reports.
pub fn badness(resident: u64, adj: i32, total: u64) -> u64 {
    if clamp_adj(adj) <= ADJ_MIN as i64 {
        return 0;
    }
    let total = total.max(1);
    let points = points(resident, adj, total).max(1);
    let scaled = (points as i128 * 1000 / total as i128).clamp(0, 2000);
    scaled as u64
}

/// Picks the victim among `candidates` with `total` pages of memory.
///
/// Protected and exempt candidates are skipped. The first dying candidate
/// seen (that is not skipped) ends the search with [`Choice::Wait`]. Else
/// the highest score wins, the earliest on a tie.
pub fn select<Id>(candidates: impl IntoIterator<Item = Candidate<Id>>, total: u64) -> Choice<Id> {
    let mut best: Option<(i64, Id)> = None;
    for c in candidates {
        if c.protected || clamp_adj(c.adj) <= ADJ_MIN as i64 {
            continue;
        }
        if c.dying {
            return Choice::Wait(c.id);
        }
        let score = points(c.resident, c.adj, total);
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((score, c.id));
        }
    }
    best.map_or(Choice::Nothing, |(_, id)| Choice::Kill(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: u32, resident: u64, adj: i32) -> Candidate<u32> {
        Candidate { id, resident, adj, protected: false, dying: false }
    }

    #[test]
    fn biggest_wins_earliest_on_tie() {
        assert_eq!(select([cand(1, 10, 0), cand(2, 30, 0), cand(3, 30, 0)], 1000), Choice::Kill(2));
        assert_eq!(select::<u32>([], 1000), Choice::Nothing);
    }

    #[test]
    fn adjustment_shifts_the_score() {
        // 1000 is all of memory: it outweighs any resident size.
        assert_eq!(select([cand(1, 500, 0), cand(2, 1, 1000)], 1000), Choice::Kill(2));
        // -500 takes half of memory off.
        assert_eq!(select([cand(1, 400, -500), cand(2, 100, 0)], 1000), Choice::Kill(2));
        // Out-of-range values are clamped.
        assert_eq!(points(0, 5000, 1000), 1000);
        assert_eq!(points(0, i32::MIN, 1000), -1000);
    }

    #[test]
    fn exempt_and_protected_are_skipped() {
        let mut init = cand(1, 900, 0);
        init.protected = true;
        assert_eq!(select([init, cand(2, 5, ADJ_MIN), cand(3, 1, 0)], 1000), Choice::Kill(3));
        assert_eq!(select([init, cand(2, 5, ADJ_MIN)], 1000), Choice::Nothing);
    }

    #[test]
    fn dying_is_waited_for() {
        let mut dying = cand(2, 1, 0);
        dying.dying = true;
        assert_eq!(select([cand(1, 100, 0), dying, cand(3, 200, 0)], 1000), Choice::Wait(2));
        // An exempt candidate that is dying does not hold the search up.
        let mut exempt = cand(4, 1, ADJ_MIN);
        exempt.dying = true;
        assert_eq!(select([exempt, cand(1, 100, 0)], 1000), Choice::Kill(1));
    }

    #[test]
    fn no_overflow() {
        assert_eq!(points(u64::MAX, ADJ_MAX, u64::MAX), i64::MAX);
        assert_eq!(select([cand(1, u64::MAX, 0), cand(2, 5, 1000)], u64::MAX), Choice::Kill(1));
    }

    #[test]
    fn badness_scale() {
        assert_eq!(badness(500, ADJ_MIN, 1000), 0);
        assert_eq!(badness(0, 0, 1000), 1);
        assert_eq!(badness(500, 0, 1000), 500);
        assert_eq!(badness(1000, 1000, 1000), 2000);
        assert_eq!(badness(10, -900, 1000), 1);
        assert_eq!(badness(5, 0, 0), 2000);
    }

    #[test]
    fn low_memory() {
        assert!(is_low(LOW_PAGES - 1));
        assert!(!is_low(LOW_PAGES));
    }
}
