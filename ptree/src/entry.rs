use crate::{ActionInsert, Node, Prefix, PrefixTree};

pub enum Entry<'a, P, T> {
    /// The entry is not present in the tree.
    Vacant(VacantEntry<'a, P, T>),
    /// The entry is already present in the tree.
    Occupied(OccupiedEntry<'a, P, T>),
}

pub struct VacantEntry<'a, P, T> {
    pub map: &'a mut PrefixTree<P, T>,
    pub prefix: P,
    pub index: usize,
    pub direction: ActionInsert<P>,
}

pub struct OccupiedEntry<'a, P, T> {
    pub node: &'a mut Node<P, T>,
}

impl<'a, P, T> VacantEntry<'a, P, T>
where
    P: Prefix,
{
    fn _insert(self, v: T) -> &'a mut Node<P, T> {
        match self.direction {
            ActionInsert::Found => {
                let node = &mut self.map.nodes[self.index];
                self.map.count += 1;
                node.value = Some(v);
                node
            }
            ActionInsert::NewLeaf { bit } => {
                let new = self.map.new_node(self.prefix, Some(v));
                self.map.set_child(self.index, new, bit);
                &mut self.map.nodes[new]
            }
            ActionInsert::NewChild { bit, child_bit } => {
                let new = self.map.new_node(self.prefix, Some(v));
                let child = self.map.set_child(self.index, new, bit).unwrap();
                self.map.set_child(new, child, child_bit);
                &mut self.map.nodes[new]
            }
            ActionInsert::NewBranch {
                branch_prefix,
                bit,
                prefix_bit,
            } => {
                let branch = self.map.new_node(branch_prefix, None);
                let new = self.map.new_node(self.prefix, Some(v));
                let child = self.map.set_child(self.index, branch, bit).unwrap();
                self.map.set_child(branch, new, prefix_bit);
                self.map.set_child(branch, child, !prefix_bit);
                &mut self.map.nodes[new]
            }
            ActionInsert::Next { .. } => unreachable!(),
        }
    }
}

impl<'a, P, T> Entry<'a, P, T>
where
    P: Prefix,
{
    #[inline(always)]
    pub fn or_insert_with<F: FnOnce() -> T>(self, default: F) -> &'a mut T {
        match self {
            Entry::Vacant(e) => e._insert(default()).value.as_mut().unwrap(),
            Entry::Occupied(e) => e.node.value.get_or_insert_with(default),
        }
    }
}

impl<'a, P, T> Entry<'a, P, T>
where
    P: Prefix,
    T: Default,
{
    #[allow(clippy::unwrap_or_default)]
    #[inline(always)]
    pub fn or_default(self) -> &'a mut T {
        self.or_insert_with(Default::default)
    }
}
