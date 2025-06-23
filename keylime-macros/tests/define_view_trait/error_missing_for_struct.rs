use keylime_macros::define_view_trait;

#[define_view_trait]        // ← missing `for_struct = "..."`
struct BadView {
    x: u8,
}

fn main() {}
