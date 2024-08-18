use crate::{Entry, OccupiedEntry, Prefix, VacantEntry};

#[derive(Clone)]
pub struct PrefixTree<P, T> {
    pub nodes: Vec<Node<P, T>>,
    free: Vec<usize>,
    pub count: usize,
}

pub enum Action {
    /// The prefix is already reached.
    Found,
    /// Enter the next index and search again.
    Next { next: usize, bit: bool },
    /// The node was not found,
    NotFound,
}

pub enum ActionInsert<P> {
    // Found same prefix node.
    Found,
    // New branch.
    Next {
        next: usize,
        bit: bool,
    },
    // New leaf node.
    NewLeaf {
        bit: bool,
    },
    // New child node.
    NewChild {
        bit: bool,
        child_bit: bool,
    },
    // New branch node.
    NewBranch {
        branch_prefix: P,
        bit: bool,
        prefix_bit: bool,
    },
}

pub fn prefix_bit<P: Prefix>(branch: &P, child: &P) -> bool {
    child.is_bit_set(branch.prefix_len())
}

impl<P, T> Default for PrefixTree<P, T>
where
    P: Prefix,
{
    fn default() -> Self {
        Self {
            nodes: vec![Node::new()],
            free: Vec::new(),
            count: 0,
        }
    }
}

impl<P, T> PrefixTree<P, T>
where
    P: Prefix,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline(always)]
    pub fn prefix_match(&self, index: usize, prefix: &P) -> Action {
        let p = &self.nodes[index].prefix;
        if p.equal(prefix) {
            Action::Found
        } else {
            let bit = prefix_bit(p, prefix);
            match self.get_child(index, bit) {
                Some(child) if self.nodes[child].prefix.contains(prefix) => {
                    Action::Next { next: child, bit }
                }
                _ => Action::NotFound,
            }
        }
    }

    #[inline(always)]
    fn prefix_match_insert(&self, index: usize, prefix: &P) -> ActionInsert<P> {
        let p = &self.nodes[index].prefix;
        if p.equal(prefix) {
            ActionInsert::Found
        } else {
            let bit = prefix_bit(p, prefix);
            if let Some(child) = self.get_child(index, bit) {
                let child_prefix = &self.nodes[child].prefix;
                if child_prefix.contains(prefix) {
                    ActionInsert::Next { next: child, bit }
                } else if prefix.contains(child_prefix) {
                    ActionInsert::NewChild {
                        bit,
                        child_bit: prefix_bit(prefix, child_prefix),
                    }
                } else {
                    let branch_prefix = prefix.common_prefix(child_prefix);
                    let prefix_bit = prefix_bit(&branch_prefix, prefix);
                    ActionInsert::NewBranch {
                        branch_prefix,
                        bit,
                        prefix_bit,
                    }
                }
            } else {
                ActionInsert::NewLeaf { bit }
            }
        }
    }

    #[inline(always)]
    pub fn new_node(&mut self, prefix: P, value: Option<T>) -> usize {
        if value.is_some() {
            self.count += 1;
        }
        if let Some(index) = self.free.pop() {
            let node = &mut self.nodes[index];
            node.prefix = prefix;
            node.value = value;
            node.parent = None;
            node.left = None;
            node.right = None;
            index
        } else {
            let index = self.nodes.len();
            self.nodes.push(Node {
                prefix,
                value,
                parent: None,
                left: None,
                right: None,
            });
            index
        }
    }

    #[inline(always)]
    pub fn get_child(&self, index: usize, bit: bool) -> Option<usize> {
        if bit {
            self.nodes[index].right
        } else {
            self.nodes[index].left
        }
    }

    #[inline(always)]
    pub fn set_child(&mut self, index: usize, child: usize, bit: bool) -> Option<usize> {
        self.nodes[child].parent.replace(index);
        if bit {
            self.nodes[index].right.replace(child)
        } else {
            self.nodes[index].left.replace(child)
        }
    }

    #[inline(always)]
    fn clear_child(&mut self, index: usize, right: bool) -> Option<usize> {
        if right {
            self.nodes[index].right.take()
        } else {
            self.nodes[index].left.take()
        }
    }

    pub fn insert(&mut self, prefix: P, value: T) -> Option<T> {
        let mut index = 0;
        loop {
            match self.prefix_match_insert(index, &prefix) {
                ActionInsert::Next { next, bit: _ } => index = next,
                ActionInsert::Found => {
                    let prev_value = self.nodes[index].value.take();
                    if prev_value.is_none() {
                        self.count += 1;
                    }
                    self.nodes[index].value = Some(value);
                    return prev_value;
                }
                ActionInsert::NewLeaf { bit } => {
                    let child = self.new_node(prefix, Some(value));
                    self.set_child(index, child, bit);
                    return None;
                }
                ActionInsert::NewChild { bit, child_bit } => {
                    let node = self.new_node(prefix, Some(value));
                    let child = self.set_child(index, node, bit).unwrap();
                    self.set_child(node, child, child_bit);
                    return None;
                }
                ActionInsert::NewBranch {
                    branch_prefix,
                    bit,
                    prefix_bit,
                } => {
                    let branch = self.new_node(branch_prefix, None);
                    let node = self.new_node(prefix, Some(value));
                    let child = self.set_child(index, branch, bit).unwrap();
                    self.set_child(branch, node, prefix_bit);
                    self.set_child(branch, child, !prefix_bit);
                    return None;
                }
            }
        }
    }

    pub fn get(&self, prefix: &P) -> Option<&T> {
        let mut index = 0;
        loop {
            match self.prefix_match(index, prefix) {
                Action::Found => return self.nodes[index].value.as_ref(),
                Action::Next { next, .. } => index = next,
                Action::NotFound => return None,
            }
        }
    }

    pub fn get_mut(&mut self, prefix: &P) -> Option<&mut T> {
        let mut index = 0;
        loop {
            match self.prefix_match(index, prefix) {
                Action::Found => return self.nodes[index].value.as_mut(),
                Action::Next { next, .. } => index = next,
                Action::NotFound => return None,
            }
        }
    }

    pub fn entry(&mut self, prefix: P) -> Entry<'_, P, T> {
        let mut index = 0;
        loop {
            match self.prefix_match_insert(index, &prefix) {
                ActionInsert::Next { next, .. } => index = next,
                ActionInsert::Found if self.nodes[index].value.is_some() => {
                    return Entry::Occupied(OccupiedEntry {
                        node: &mut self.nodes[index],
                    })
                }
                direction => {
                    return Entry::Vacant(VacantEntry {
                        map: self,
                        prefix,
                        index,
                        direction,
                    })
                }
            }
        }
    }

    fn remove_node(
        &mut self,
        index: usize,
        parent: Option<usize>,
        parent_bit: bool,
        grandparent: Option<usize>,
        grandparent_bit: bool,
    ) -> (Option<T>, bool) {
        let node = &mut self.nodes[index];
        let value = node.value.take();
        let has_left = node.left.is_some();
        let has_right = node.right.is_some();

        if value.is_some() {
            self.count -= 1;
        }

        if has_left && has_right {
            // retain node when the node has both left & right.
        } else if !(has_left || has_right) {
            if let Some(parent) = parent {
                self.clear_child(parent, parent_bit);
                self.free.push(index);
                if let Some(grandparent) = grandparent {
                    if self.nodes[parent].value.is_none() {
                        if let Some(sibling) = self.get_child(parent, !parent_bit) {
                            self.set_child(grandparent, sibling, grandparent_bit);
                            return (value, true);
                        } else {
                            self.clear_child(grandparent, grandparent_bit);
                        }
                    }
                }
            }
        } else if let Some(par) = parent {
            let child_right = has_right;
            let child = self.clear_child(index, child_right).unwrap();
            self.set_child(par, child, parent_bit);
            self.free.push(index);
        }
        (value, false)
    }

    pub fn remove(&mut self, prefix: &P) -> Option<T> {
        let mut index = 0;
        let mut grandparent = None;
        let mut grandparent_bit = false;
        let mut parent = None;
        let mut parent_bit = false;

        loop {
            match self.prefix_match(index, prefix) {
                Action::Found => break,
                Action::Next { next, bit } => {
                    grandparent_bit = parent_bit;
                    parent_bit = bit;
                    grandparent = parent;
                    parent = Some(index);
                    index = next;
                }
                Action::NotFound => return None,
            }
        }
        self.remove_node(index, parent, parent_bit, grandparent, grandparent_bit)
            .0
    }

    pub fn remove_keep_tree(&mut self, prefix: &P) -> Option<T> {
        let mut index = 0;
        let value = loop {
            match self.prefix_match(index, prefix) {
                Action::Found => break self.nodes[index].value.take(),
                Action::Next { next, .. } => index = next,
                Action::NotFound => break None,
            }
        };
        if value.is_some() {
            self.count -= 1;
        }
        value
    }
}

#[derive(Clone)]
pub struct Node<P, T> {
    pub prefix: P,
    pub value: Option<T>,
    pub parent: Option<usize>,
    pub left: Option<usize>,
    pub right: Option<usize>,
}

impl<P, T> Default for Node<P, T>
where
    P: Prefix,
{
    fn default() -> Self {
        Self {
            prefix: P::zero(),
            value: None,
            parent: None,
            left: None,
            right: None,
        }
    }
}

impl<P, T> Node<P, T>
where
    P: Prefix,
{
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ip(s: &str) -> ipnet::Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn new() {
        let pm: PrefixTree<ipnet::Ipv4Net, u32> = PrefixTree::new();
        assert_eq!(pm.len(), 0);
    }

    #[test]
    fn iter() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        pm.insert(ip("192.168.0.0/22"), 1);
        pm.insert(ip("192.168.0.0/23"), 2);
        pm.insert(ip("192.168.2.0/23"), 3);
        pm.insert(ip("192.168.0.0/24"), 4);
        pm.insert(ip("192.168.2.0/24"), 5);
        assert_eq!(pm.len(), 5);
        assert_eq!(
            pm.iter().collect::<Vec<_>>(),
            vec![
                (&ip("192.168.0.0/22"), &1),
                (&ip("192.168.0.0/23"), &2),
                (&ip("192.168.0.0/24"), &4),
                (&ip("192.168.2.0/23"), &3),
                (&ip("192.168.2.0/24"), &5),
            ]
        );
    }

    #[test]
    fn get() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        pm.insert(ip("192.168.1.0/24"), 1);
        assert_eq!(pm.get(&ip("192.168.1.0/24")), Some(&1));
        assert_eq!(pm.get(&ip("192.168.2.0/24")), None);
        assert_eq!(pm.get(&ip("192.168.0.0/23")), None);
        assert_eq!(pm.get(&ip("192.168.1.128/25")), None);
    }

    #[test]
    fn get_mut() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        let prefix = ip("192.168.1.0/24");
        pm.insert(prefix, 1);
        assert_eq!(pm.get(&prefix), Some(&1));
        *pm.get_mut(&prefix).unwrap() += 1;
        assert_eq!(pm.get(&prefix), Some(&2));
    }

    #[test]
    fn entry() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        pm.insert(ip("192.168.0.0/23"), vec![1]);
        pm.entry(ip("192.168.0.0/23")).or_default().push(2);
        pm.entry(ip("192.168.0.0/24")).or_default().push(3);
        assert_eq!(pm.get(&ip("192.168.0.0/23")), Some(&vec![1, 2]));
        assert_eq!(pm.get(&ip("192.168.0.0/24")), Some(&vec![3]));
    }

    #[test]
    fn children() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        pm.insert(ip("192.168.0.0/22"), 1);
        pm.insert(ip("192.168.0.0/23"), 2);
        pm.insert(ip("192.168.2.0/23"), 3);
        pm.insert(ip("192.168.0.0/24"), 4);
        pm.insert(ip("192.168.2.0/24"), 5);

        assert_eq!(
            pm.children(&ip("192.168.0.0/23")).collect::<Vec<_>>(),
            vec![(&ip("192.168.0.0/23"), &2), (&ip("192.168.0.0/24"), &4),]
        );
    }

    #[test]
    fn remove() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        let prefix = ip("192.168.1.0/24");
        pm.insert(prefix, 1);
        assert_eq!(pm.get(&prefix), Some(&1));
        assert_eq!(pm.remove(&prefix), Some(1));
        assert_eq!(pm.get(&prefix), None);
    }

    #[test]
    fn remove_keep_tree() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        let prefix = ip("192.168.1.0/24");
        pm.insert(prefix, 1);
        assert_eq!(pm.get(&prefix), Some(&1));
        assert_eq!(pm.remove_keep_tree(&prefix), Some(1));
        assert_eq!(pm.get(&prefix), None);

        pm.insert(prefix, 1);
        assert_eq!(pm.get(&prefix), Some(&1));
    }

    #[test]
    fn ascend() {
        let mut pm: PrefixTree<ipnet::Ipv4Net, _> = PrefixTree::new();
        pm.insert(ip("0.0.0.0/0"), 1);
        pm.insert(ip("192.168.0.0/16"), 2);
        pm.insert(ip("192.192.0.0/16"), 3);
        pm.insert(ip("192.168.0.0/22"), 4);
        pm.insert(ip("192.168.0.0/23"), 5);
        pm.insert(ip("192.168.2.0/23"), 6);
        pm.insert(ip("192.168.0.0/24"), 7);
        pm.insert(ip("192.168.2.0/24"), 8);

        assert_eq!(
            pm.ascend(&ip("192.168.0.0/23")).collect::<Vec<_>>(),
            vec![
                (&ip("192.168.0.0/23"), &5),
                (&ip("192.168.0.0/22"), &4),
                (&ip("192.168.0.0/16"), &2),
                (&ip("0.0.0.0/0"), &1),
            ]
        );
    }
}
