//! BGP's MPLS labels, from chunks of the RIB's label space
//! (docs/design/mpls-label-allocation.md §5.2).
//!
//! An allocator takes a chunk from the dynamic region synchronously,
//! through the shared [`LabelSpace`](crate::rib::label_space::LabelSpace),
//! and hands out single labels inside it, lowest free first. The RIB tracks
//! the chunk, not the label. Chunk sizes adapt as FRR's bgpd does: the first
//! is 128 labels, each further one doubles up to 65536, and returning a
//! chunk resets the next size to 128. A region too full for the next size
//! still yields a smaller chunk, halving down to 128; below that,
//! allocation fails, and the next one tries again. A failure also leaves
//! the owner starved in the label space, so the RIB tells it
//! (`RibRx::LocalLabelsFreed`) once labels are freed or the range grows,
//! and it can label what went without ([`LabelChunks::take_starved`]).
//! A label of its own freed meanwhile is room too, one the RIB never
//! hears of: the chunk stays held ([`LabelChunks::take_room`]).
//!
//! A chunk whose labels are all free is not given back at once: the BGP
//! task's ILM deletions for its labels may still be on their way to the
//! RIB. [`LabelChunks::take_drained`] hands such chunks to the caller,
//! which returns them on the same channel, behind those deletions.

use std::collections::{BTreeMap, BTreeSet};

use crate::rib::client::ProtoId;
use crate::rib::label_space::SharedLabelSpace;
use crate::spf::label_block::LabelBlock;

/// The first chunk's size, and the size after a chunk goes back.
pub const CHUNK_MIN: u32 = 128;
/// The largest chunk: 1/16 of the label space, so one busy allocator
/// cannot take a greedy share.
pub const CHUNK_MAX: u32 = 65536;

/// A chunk, `[start, end)`.
#[derive(Debug)]
struct Chunk {
    end: u32,
    /// The first label never handed out.
    next: u32,
    /// Labels handed out and not freed.
    live: u32,
}

/// Labels from chunks of the RIB's label space.
#[derive(Debug)]
pub struct LabelChunks {
    /// The label space chunks come from; `None` for an allocator that may
    /// not mint (a pool worker, a per-VRF shard).
    space: Option<SharedLabelSpace>,
    /// The protocol chunks are held under.
    proto: &'static str,
    /// The instance told when room returns after a failed allocation.
    owner: Option<ProtoId>,
    /// An allocation failed since [`Self::take_starved`] last ran.
    starved: bool,
    /// A label was freed while [`Self::starved`]: what went without can
    /// have it ([`Self::take_room`]).
    room: bool,
    /// Chunks, by first label.
    chunks: BTreeMap<u32, Chunk>,
    /// Labels handed out and freed, inside the chunks.
    free: BTreeSet<u32>,
    /// The size of the next chunk.
    next_size: u32,
}

impl Default for LabelChunks {
    fn default() -> Self {
        Self::without_space()
    }
}

impl LabelChunks {
    /// An allocator taking chunks from `space` under `proto` for
    /// `owner`, the instance told when room returns.
    pub fn new(space: SharedLabelSpace, proto: &'static str, owner: ProtoId) -> Self {
        Self {
            space: Some(space),
            proto,
            owner: Some(owner),
            ..Self::without_space()
        }
    }

    /// An allocator with no label space: it hands out nothing.
    pub fn without_space() -> Self {
        Self {
            space: None,
            proto: "bgp",
            owner: None,
            starved: false,
            room: false,
            chunks: BTreeMap::new(),
            free: BTreeSet::new(),
            next_size: CHUNK_MIN,
        }
    }

    /// One label: the lowest freed one, else the next of a chunk with
    /// room, else the first of a new chunk. `None` with no label space, or
    /// when even a chunk of [`CHUNK_MIN`] labels cannot be had.
    pub fn alloc(&mut self) -> Option<u32> {
        let label = match self.free.pop_first() {
            Some(label) => label,
            None => match self.chunks.values_mut().find(|c| c.next < c.end) {
                Some(chunk) => {
                    chunk.next += 1;
                    chunk.next - 1
                }
                None => self.take_chunk()?,
            },
        };
        if let Some(chunk) = self.chunk_mut(label) {
            chunk.live += 1;
        }
        Some(label)
    }

    /// Take a chunk of the next size, or a smaller one down to
    /// [`CHUNK_MIN`] if the region has no room for it, and return its
    /// first label (handed out).
    fn take_chunk(&mut self) -> Option<u32> {
        let mut space = self.space.as_ref()?.lock();
        let mut size = self.next_size;
        let block = loop {
            if let Some(block) = space.alloc(self.proto, size) {
                break block;
            }
            if size <= CHUNK_MIN {
                // Under the lock the allocation failed under: room the
                // RIB makes from here on finds the owner starved.
                if let Some(owner) = self.owner {
                    space.starve(owner);
                }
                if !self.starved {
                    tracing::warn!(
                        proto = self.proto,
                        "label chunk: the dynamic range has no room for {CHUNK_MIN} labels"
                    );
                }
                self.starved = true;
                return None;
            }
            size /= 2;
        };
        drop(space);
        self.next_size = (size * 2).min(CHUNK_MAX);
        self.chunks.insert(
            block.start,
            Chunk {
                end: block.end,
                next: block.start + 1,
                live: 0,
            },
        );
        Some(block.start)
    }

    fn chunk_mut(&mut self, label: u32) -> Option<&mut Chunk> {
        self.chunks
            .range_mut(..=label)
            .next_back()
            .map(|(_, chunk)| chunk)
            .filter(|chunk| label < chunk.next)
    }

    /// Give back `label`. One outside every chunk, or already free, is
    /// ignored.
    pub fn free(&mut self, label: u32) {
        let in_use = self.chunk_mut(label).is_some_and(|chunk| chunk.live > 0);
        if !in_use || !self.free.insert(label) {
            return;
        }
        if let Some(chunk) = self.chunk_mut(label) {
            chunk.live -= 1;
        }
        self.room |= self.starved;
    }

    /// Whether an allocation failed since the last call: the caller, told
    /// that room returned, labels what went without.
    pub fn take_starved(&mut self) -> bool {
        self.room = false;
        std::mem::take(&mut self.starved)
    }

    /// Whether a label was freed since an allocation failed: the caller
    /// labels what went without from it, with no word from the RIB, which
    /// sees no change while the chunk stays held. A failure again starves
    /// the allocator again.
    pub fn take_room(&mut self) -> bool {
        let room = std::mem::take(&mut self.room);
        if room {
            self.starved = false;
        }
        room
    }

    /// Take out the chunks whose labels are all free, for the caller to
    /// return to the RIB behind its ILM deletions for them. The next chunk
    /// is [`CHUNK_MIN`] again if any went.
    pub fn take_drained(&mut self) -> Vec<LabelBlock> {
        let drained: Vec<u32> = self
            .chunks
            .iter()
            .filter(|(_, chunk)| chunk.live == 0)
            .map(|(start, _)| *start)
            .collect();
        let mut blocks = Vec::new();
        for start in drained {
            let chunk = self.chunks.remove(&start).expect("listed");
            self.free
                .retain(|label| !(start..chunk.end).contains(label));
            blocks.push(LabelBlock {
                start,
                end: chunk.end,
            });
        }
        if !blocks.is_empty() {
            self.next_size = CHUNK_MIN;
        }
        blocks
    }

    /// The chunks held, `[start, end)`, for tests.
    #[cfg(test)]
    pub fn chunks(&self) -> Vec<LabelBlock> {
        self.chunks
            .iter()
            .map(|(start, chunk)| LabelBlock {
                start: *start,
                end: chunk.end,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(start: u32, end: u32) -> LabelBlock {
        LabelBlock { start, end }
    }

    fn owner() -> ProtoId {
        ProtoId::from_raw(7)
    }

    /// Chunks start at 128 labels from 24000, the lowest label first, and
    /// double as each fills.
    #[test]
    fn chunks_start_small_and_double() {
        let space = SharedLabelSpace::default();
        let mut labels = LabelChunks::new(space.clone(), "bgp", owner());
        assert_eq!(labels.alloc(), Some(24000));
        assert_eq!(labels.alloc(), Some(24001));
        for _ in 2..128 {
            labels.alloc().unwrap();
        }
        assert_eq!(labels.chunks(), vec![block(24000, 24128)]);
        assert_eq!(labels.alloc(), Some(24128));
        assert_eq!(
            labels.chunks(),
            vec![block(24000, 24128), block(24128, 24384)],
            "the second chunk is 256"
        );
        assert_eq!(
            space.lock().held_blocks(),
            vec![
                (block(24000, 24128), "bgp".to_string()),
                (block(24128, 24384), "bgp".to_string()),
            ]
        );
    }

    /// The size stops doubling at 65536.
    #[test]
    fn chunks_stop_growing_at_the_maximum() {
        let space = SharedLabelSpace::default();
        let mut labels = LabelChunks::new(space, "bgp", owner());
        let mut sizes = Vec::new();
        for _ in 0..12 {
            let start = labels.take_chunk().unwrap();
            let chunk = &labels.chunks[&start];
            sizes.push(chunk.end - start);
        }
        assert_eq!(
            sizes,
            vec![
                128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 65536, 65536
            ]
        );
    }

    /// A region with no room for the next size still yields a smaller
    /// chunk, down to 128; with less than that, allocation fails, and
    /// succeeds again once there is room.
    #[test]
    fn a_full_region_yields_smaller_chunks_then_none() {
        let space = SharedLabelSpace::default();
        space.lock().set_dynamic(24000, 24000 + 128 + 256 + 200 - 1);
        let mut labels = LabelChunks::new(space.clone(), "bgp", owner());
        for _ in 0..(128 + 256) {
            labels.alloc().unwrap();
        }
        // Next would be 512; 200 labels are left, so 128.
        assert_eq!(labels.alloc(), Some(24384));
        assert_eq!(labels.chunks().last(), Some(&block(24384, 24512)));
        for _ in 1..128 {
            labels.alloc().unwrap();
        }
        assert_eq!(labels.alloc(), None, "72 labels left: no chunk");
        space.lock().set_dynamic(24000, 30000);
        assert_eq!(labels.alloc(), Some(24512), "room again");
    }

    /// A freed label is handed out again, lowest first; a label outside
    /// the chunks, or freed twice, changes nothing.
    #[test]
    fn freed_labels_are_reused_lowest_first() {
        let space = SharedLabelSpace::default();
        let mut labels = LabelChunks::new(space, "bgp", owner());
        for _ in 0..5 {
            labels.alloc().unwrap();
        }
        labels.free(24003);
        labels.free(24001);
        labels.free(24001);
        labels.free(99999);
        assert_eq!(labels.alloc(), Some(24001));
        assert_eq!(labels.alloc(), Some(24003));
        assert_eq!(labels.alloc(), Some(24005));
    }

    /// A chunk whose labels are all free is taken out for the caller to
    /// return, and the next chunk is 128 again; one with a label in use
    /// stays. Nothing goes back to the label space until the caller says
    /// so.
    #[test]
    fn a_drained_chunk_is_handed_back_and_resets_the_size() {
        let space = SharedLabelSpace::default();
        let mut labels = LabelChunks::new(space.clone(), "bgp", owner());
        for _ in 0..129 {
            labels.alloc().unwrap();
        }
        assert!(labels.take_drained().is_empty(), "all in use");
        for label in 24000..24128 {
            labels.free(label);
        }
        assert_eq!(labels.take_drained(), vec![block(24000, 24128)]);
        assert_eq!(labels.chunks(), vec![block(24128, 24384)]);
        assert_eq!(space.lock().held_blocks().len(), 2, "the caller returns it");
        assert_eq!(labels.next_size, CHUNK_MIN);
        assert_eq!(labels.alloc(), Some(24129), "from the chunk still held");
    }

    /// A failure leaves the owner starved in the label space, under the
    /// same lock, so the RIB tells it when room returns; the allocator
    /// remembers it until asked. A success starves no one.
    #[test]
    fn a_failure_starves_the_owner_until_asked() {
        let space = SharedLabelSpace::default();
        space.lock().set_dynamic(24000, 24127);
        let mut labels = LabelChunks::new(space.clone(), "bgp", owner());
        for _ in 0..128 {
            labels.alloc().unwrap();
        }
        assert!(space.lock().take_starved().is_empty());
        assert!(!labels.take_starved());
        assert_eq!(labels.alloc(), None);
        assert_eq!(space.lock().take_starved(), [owner()].into());
        assert!(labels.take_starved());
        assert!(!labels.take_starved(), "asked once");
        space.lock().set_dynamic(24000, 30000);
        assert_eq!(labels.alloc(), Some(24128));
        assert!(space.lock().take_starved().is_empty());
        assert!(!labels.take_starved());
    }

    /// A label freed while starved is room the allocator reports itself
    /// (the RIB sees no change: the chunk stays held), and hands out; a
    /// label freed while not starved is not.
    #[test]
    fn a_label_freed_while_starved_is_room() {
        let space = SharedLabelSpace::default();
        space.lock().set_dynamic(24000, 24127);
        let mut labels = LabelChunks::new(space.clone(), "bgp", owner());
        for _ in 0..128 {
            labels.alloc().unwrap();
        }
        labels.free(24010);
        assert!(!labels.take_room(), "not starved: nothing went without");
        assert_eq!(labels.alloc(), Some(24010));
        assert_eq!(labels.alloc(), None);
        assert!(!labels.take_room());
        labels.free(24005);
        assert!(labels.take_room());
        assert!(!labels.take_room(), "asked once");
        assert!(!labels.take_starved(), "the retry clears the starving");
        assert_eq!(labels.alloc(), Some(24005));
        assert_eq!(labels.alloc(), None, "starved again");
        labels.free(24006);
        assert!(labels.take_starved());
        assert!(!labels.take_room(), "a full retry covers the room");
    }

    /// Without a label space nothing is handed out.
    #[test]
    fn no_label_space_no_labels() {
        let mut labels = LabelChunks::without_space();
        assert_eq!(labels.alloc(), None);
        assert!(labels.take_drained().is_empty());
    }
}
