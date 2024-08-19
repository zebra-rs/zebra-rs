use crate::{prefix_bit, Action, Prefix, PrefixTree};

#[derive(Clone)]
pub struct Iter<'a, P, T> {
    tree: &'a PrefixTree<P, T>,
    nodes: Vec<usize>,
}

impl<'a, P, T> Iterator for Iter<'a, P, T> {
    type Item = (&'a P, &'a T);

    fn next(&mut self) -> Option<(&'a P, &'a T)> {
        while let Some(cur) = self.nodes.pop() {
            let node = &self.tree.nodes[cur];
            if let Some(right) = node.right {
                self.nodes.push(right);
            }
            if let Some(left) = node.left {
                self.nodes.push(left);
            }
            if let Some(v) = &node.value {
                return Some((&node.prefix, v));
            }
        }
        None
    }
}

impl<'a, P, T> IntoIterator for &'a PrefixTree<P, T> {
    type Item = (&'a P, &'a T);

    type IntoIter = Iter<'a, P, T>;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            tree: self,
            nodes: vec![0],
        }
    }
}

impl<P, T> PrefixTree<P, T> {
    #[inline(always)]
    pub fn iter(&self) -> Iter<'_, P, T> {
        self.into_iter()
    }
}

impl<P, T> PrefixTree<P, T>
where
    P: Prefix,
{
    pub fn children(&self, prefix: &P) -> Iter<'_, P, T> {
        let mut index = 0;
        let mut p = &self.nodes[index].prefix;
        let nodes = loop {
            if p.equal(prefix) {
                break vec![index];
            }
            let bit = prefix_bit(p, prefix);
            match self.get_child(index, bit) {
                Some(c) => {
                    p = &self.nodes[c].prefix;
                    if p.contains(prefix) {
                        index = c;
                    } else if prefix.contains(p) {
                        break vec![c];
                    } else {
                        break vec![];
                    }
                }
                None => break vec![],
            }
        };
        Iter { tree: self, nodes }
    }
}

#[derive(Clone)]
pub struct Ascend<'a, P, T> {
    tree: &'a PrefixTree<P, T>,
    nodes: Vec<usize>,
}

impl<'a, P, T> Iterator for Ascend<'a, P, T> {
    type Item = (&'a P, &'a T);

    fn next(&mut self) -> Option<(&'a P, &'a T)> {
        while let Some(cur) = self.nodes.pop() {
            let node = &self.tree.nodes[cur];
            if let Some(parent) = node.parent {
                self.nodes.push(parent);
            }
            if let Some(v) = &node.value {
                return Some((&node.prefix, v));
            }
        }
        None
    }
}

impl<P, T> PrefixTree<P, T>
where
    P: Prefix,
{
    pub fn ascend(&self, prefix: &P) -> Ascend<'_, P, T> {
        let mut index = 0;
        let nodes = loop {
            match self.prefix_match(index, prefix) {
                Action::Found => break vec![index],
                Action::Next { next, .. } => index = next,
                Action::NotFound => break vec![],
            }
        };
        Ascend { tree: self, nodes }
    }
}
