#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretFilter<'a> {
    All,
    Untagged,
    Tag(&'a str),
}
