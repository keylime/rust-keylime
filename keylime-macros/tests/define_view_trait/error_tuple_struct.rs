use keylime_macros::define_view_trait;

struct Target { inner: u8 }

#[define_view_trait(for_struct = "Target")]
struct BadView(u8);          // this is a tuple struct, should error

fn main() {}
