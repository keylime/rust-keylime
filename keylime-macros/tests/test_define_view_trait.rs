// Drive all .rs files in tests/ui/ through trybuild.
#[test]
fn test_define_view_trait() {
    let t = trybuild::TestCases::new();
    t.pass("tests/define_view_trait/sanity.rs");
    t.compile_fail("tests/define_view_trait/error_missing_for_struct.rs");
    t.compile_fail("tests/define_view_trait/error_tuple_struct.rs");
    t.compile_fail("tests/define_view_trait/error_missing_transform_fn.rs");
    t.compile_fail("tests/define_view_trait/error_missing_transform_err.rs");
}
