use keylime_macros::define_view_trait;

#[derive(Copy, Clone, Debug, PartialEq)]
struct CustomID {
    id: u32,
}

struct MyCfg {
    a: String,
    b: u32,
    c: CustomID,
}

#[define_view_trait(for_struct = "MyCfg")]
struct MyView {
    a: String,
    b: u32,
    #[copy]
    c: CustomID,
}

#[test]
fn view_trait_works() {
    let cfg = MyCfg {
        a: "hello".into(),
        b: 99,
        c: CustomID { id: 123 },
    };

    // the generated trait is MyViewTrait
    assert_eq!(cfg.a(), "hello");
    assert_eq!(cfg.b(), 99);
    assert_eq!(cfg.c(), CustomID { id: 123 });
}
