/// Generic result for table diff operations
#[derive(Debug)]
pub struct TableDiffResult<'a, K, V> {
    pub only_curr: Vec<(&'a K, &'a V)>,
    pub only_next: Vec<(&'a K, &'a V)>,
    pub different: Vec<(&'a K, &'a V, &'a V)>,
    pub identical: Vec<(&'a K, &'a V)>,
}

/// Generic table diff implementation using sorted iterators
pub fn table_diff<'a, K, V, I>(curr_iter: I, next_iter: I) -> TableDiffResult<'a, K, V>
where
    K: Ord,
    V: PartialEq,
    I: Iterator<Item = (&'a K, &'a V)>,
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
        match curr_key.cmp(next_key) {
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
