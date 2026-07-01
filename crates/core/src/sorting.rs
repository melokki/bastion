use crate::secret::Secret;
use std::cmp::Ordering;

pub fn visible_secret_order(left: &&Secret, right: &&Secret) -> Ordering {
    left.title()
        .to_lowercase()
        .cmp(&right.title().to_lowercase())
        .then_with(|| left.created_at().cmp(&right.created_at()))
        .then_with(|| left.id().cmp(&right.id()))
}
