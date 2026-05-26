/// Generic result for table diff operations
#[derive(Debug)]
pub struct TableDiffResult<'a, K, V> {
    pub only_curr: Vec<(K, &'a V)>,
    pub only_next: Vec<(K, &'a V)>,
    pub different: Vec<(K, &'a V, &'a V)>,
    pub identical: Vec<(K, &'a V)>,
}

/// Generic table diff implementation using sorted iterators.
/// Keys are taken by value because `prefix-trie` 0.9 yields owned
/// prefixes (which are `Copy`), and `BTreeMap` callers can adapt
/// with `.iter().map(|(&k, v)| (k, v))`.
pub fn table_diff<'a, K, V, I1, I2>(curr_iter: I1, next_iter: I2) -> TableDiffResult<'a, K, V>
where
    K: Ord + Copy,
    V: PartialEq,
    I1: Iterator<Item = (K, &'a V)>,
    I2: Iterator<Item = (K, &'a V)>,
{
    let mut res = TableDiffResult {
        only_curr: vec![],
        only_next: vec![],
        different: vec![],
        identical: vec![],
    };

    let mut curr_iter = curr_iter.peekable();
    let mut next_iter = next_iter.peekable();

    while let (Some(&(curr_key, curr_value)), Some(&(next_key, next_value))) =
        (curr_iter.peek(), next_iter.peek())
    {
        match curr_key.cmp(&next_key) {
            std::cmp::Ordering::Less => {
                // curr_key is only in curr
                res.only_curr.push((curr_key, curr_value));
                curr_iter.next();
            }
            std::cmp::Ordering::Greater => {
                // next_key is only in next
                res.only_next.push((next_key, next_value));
                next_iter.next();
            }
            std::cmp::Ordering::Equal => {
                // keys are equal; compare values
                if curr_value == next_value {
                    res.identical.push((curr_key, curr_value));
                } else {
                    res.different.push((curr_key, curr_value, next_value));
                }
                curr_iter.next();
                next_iter.next();
            }
        }
    }

    // Deal with the rest of curr
    for (key, value) in curr_iter {
        res.only_curr.push((key, value));
    }

    // Deal with the rest of next
    for (key, value) in next_iter {
        res.only_next.push((key, value));
    }

    res
}
