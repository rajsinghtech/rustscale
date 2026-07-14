//! Port of `ringlog_test.go`.

use crate::*;

#[test]
fn test_ring_log() {
    const NUM_ITEMS: usize = 10;
    let rb = RingLog::<i32>::new(NUM_ITEMS);

    // Add 0..9 (one short of full).
    for i in 0..(NUM_ITEMS as i32 - 1) {
        rb.add(i);
    }

    // NotFull: 9 items, in order 0..9.
    assert_eq!(rb.len(), NUM_ITEMS - 1);
    let all = rb.get_all();
    assert_eq!(all, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);

    // Full: add two more, evicting the two oldest.
    rb.add(98);
    rb.add(99);
    assert_eq!(rb.len(), NUM_ITEMS);
    let all = rb.get_all();
    assert_eq!(all, vec![1, 2, 3, 4, 5, 6, 7, 8, 98, 99]);

    // Clear.
    rb.clear();
    assert_eq!(rb.len(), 0);
    assert!(rb.is_empty());
    assert!(rb.get_all().is_empty());
}

#[test]
fn zero_capacity_drops_all() {
    let rb = RingLog::<i32>::new(0);
    rb.add(1);
    rb.add(2);
    assert_eq!(rb.len(), 0);
    assert!(rb.get_all().is_empty());
}

#[test]
fn single_capacity_keeps_latest() {
    let rb = RingLog::<i32>::new(1);
    rb.add(10);
    assert_eq!(rb.get_all(), vec![10]);
    rb.add(20);
    assert_eq!(rb.get_all(), vec![20]);
}

#[test]
fn wrap_around_multiple_times() {
    let rb = RingLog::<i32>::new(3);
    for i in 0..10 {
        rb.add(i);
    }
    // After inserting 0..9 with capacity 3, the last 3 are 7, 8, 9.
    assert_eq!(rb.get_all(), vec![7, 8, 9]);
    assert_eq!(rb.len(), 3);
}

#[test]
fn generic_type_string() {
    let rb = RingLog::<String>::new(2);
    rb.add("a".to_string());
    rb.add("b".to_string());
    rb.add("c".to_string()); // evicts "a"
    assert_eq!(rb.get_all(), vec!["b".to_string(), "c".to_string()]);
}

#[test]
fn default_is_empty_zero_capacity() {
    let rb: RingLog<i32> = RingLog::default();
    assert!(rb.is_empty());
    rb.add(42);
    assert_eq!(rb.len(), 0);
}
