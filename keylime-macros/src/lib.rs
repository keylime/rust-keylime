use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Attribute, Fields, Ident, ItemStruct, Lit, Meta, Token, Type,
};

/// Parses the '#[transform(...)]' attribute
/// `#[transform(using = my_transform, error = MyError)]`
struct TransformAttribute {
    using_kw: Ident,
    _eq_token1: Token![=],
    transform_fn: Ident,
    _comma: Token![,],
    error_kw: Ident,
    _eq_token2: Token![=],
    error_type: Type,
}

impl Parse for TransformAttribute {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let parsed = Self {
            using_kw: input.parse()?,
            _eq_token1: input.parse()?,
            transform_fn: input.parse()?,
            _comma: input.parse()?,
            error_kw: input.parse()?,
            _eq_token2: input.parse()?,
            error_type: input.parse()?,
        };

        // Ensure the identifiers are what we expect.
        if parsed.using_kw != "using" {
            return Err(syn::Error::new(
                parsed.using_kw.span(),
                "expected `using`",
            ));
        }
        if parsed.error_kw != "error" {
            return Err(syn::Error::new(
                parsed.error_kw.span(),
                "expected `error`",
            ));
        }

        Ok(parsed)
    }
}

/// Checks if a type is a primitive that is known to be `Copy`.
fn is_known_copy_type(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(ident) = type_path.path.get_ident() {
            let type_str = ident.to_string();
            matches!(
                type_str.as_str(),
                "bool"
                    | "char"
                    | "f32"
                    | "f64"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
            )
        } else {
            false
        }
    } else {
        false
    }
}

/// Checks if a field has the `#[copy]` attribute.
fn has_copy_attribute(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("copy"))
}

/// Helper function to find and parse our `#[transform(...)]` attribute from a field's attributes.
fn get_transform_attribute(
    attrs: &[Attribute],
) -> syn::Result<Option<TransformAttribute>> {
    // Find an attribute where the path is the identifier "transform".
    if let Some(attr) = attrs.iter().find(|a| a.path().is_ident("transform"))
    {
        let parsed_attr = attr.parse_args::<TransformAttribute>()?;
        Ok(Some(parsed_attr))
    } else {
        Ok(None)
    }
}

#[proc_macro_attribute]
/// Procedural macro to define a trait view for a configuration struct.
///
/// This macro generates a trait based on the fields of the annotated "view struct"
/// and implements that trait for a target struct.
///
/// # Example
///
/// Given this setup code:
///
/// ```rust,ignore
/// pub enum ParsingError { Empty }
/// pub fn parse_string_list(s: &str) -> Result<Vec<&str>, ParsingError> { /* ... */ }
///
/// pub struct KeylimeConfig {
///     pub port: u16,
///     pub api_versions: String,
///     pub attribute: SomeCopyType,
/// }
///
/// // You write this view struct:
/// #[define_view_trait(for_struct = "KeylimeConfig")]
/// struct AgentView {
///     // A regular field for a Copy type, returns a copy.
///     port: u16,
///
///     // A custom type that implements Copy trait, annotated to get a copy
///     #[copy]
///     pub attribute: SomeCopyType,
///     // An annotated field. The field's type `Vec<String>` is the desired
///     // output type. The annotation provides the parser and error type.
///     #[transform(using = parse_string_list, error = ParsingError)]
///     api_versions: Vec<String>,
/// }
/// ```
///
/// The macro expands into the following code:
///
/// ```rust,ignore
/// #[allow(dead_code)]
/// struct AgentView {
///     port: u16,
///     api_versions: String,
/// }
///
/// pub trait AgentViewTrait {
///     // Getter for the regular copy field:
///     fn port(&self) -> u16;
///
///     // Getter for annotated Copy type field:
///     pub attribute(&self) -> SomeCopyType,
///
///     // Getter for the annotated field with its custom return type:
///     fn api_versions(&self) -> Result<Vec<String>, ParsingError>;
/// }
///
/// impl AgentViewTrait for KeylimeConfig {
///     // Implementation for the regular Copy type getter:
///     fn port(&self) -> u16 {
///         self.port
///     }
///
///     // Getter for annotated Copy type field:
///     fn attribute(&self) -> SomeCopyType {
///         self.attribute
///     }
///
///     // Implementation for the annotated getter, calling the specified function:
///     fn api_versions(&self) -> Result<Vec<String>, ParsingError> {
///         parse_string_list(&self.api_versions)
///     }
/// }
/// ```
///
/// # Attributes
///
/// - `#[define_view_trait(for_struct = "MainStruct")]`: Specifies the main
///   configuration struct to implement the trait for.
/// - `#[copy]`: An optional field-level attribute to specify if the getter should return a copy of
///   the field value. Should be used only for fields of Copy types
/// - `#[transform(using = parser_fn, error = ReturnType)]`: An optional field-level attribute to specify
///   a custom transforming function for a field.
pub fn define_view_trait(
    attr: TokenStream,
    item: TokenStream,
) -> TokenStream {
    // Parse the `for_struct = "SomeStruct"`
    let metas = parse_macro_input!(attr with syn::punctuated::Punctuated::<Meta, Token![,]>::parse_terminated);
    let main_struct_ident = if let Some(Meta::NameValue(nv)) = metas.first() {
        if nv.path.get_ident().is_some_and(|i| i == "for_struct") {
            if let syn::Expr::Lit(expr_lit) = &nv.value {
                if let Lit::Str(lit_str) = &expr_lit.lit {
                    lit_str.parse::<Ident>()
                } else {
                    Err(syn::Error::new_spanned(
                        &nv.value,
                        "Attribute value must be a string literal.",
                    ))
                }
            } else {
                Err(syn::Error::new_spanned(
                    &nv.value,
                    "Attribute value must be a string literal.",
                ))
            }
        } else {
            Err(syn::Error::new_spanned(
                &nv.path,
                "Expected attribute `for_struct`.",
            ))
        }
    } else {
        Err(syn::Error::new(
            metas.span(),
            "Usage: #[define_view_trait(for_struct = \"MainStruct\")]",
        ))
    };

    // Exit with a compiler error if parsing the attribute failed
    let main_struct_ident = match main_struct_ident {
        Ok(ident) => ident,
        Err(e) => return e.into_compile_error().into(),
    };

    let mut view_struct = parse_macro_input!(item as ItemStruct);
    // Add #[allow(dead_code)] to the view struct, as its fields are markers, not directly used.
    view_struct
        .attrs
        .push(syn::parse_quote!(#[allow(dead_code)]));

    // Derive the trait name using the "Trait" suffix
    let view_name = &view_struct.ident;
    let trait_ident =
        Ident::new(&format!("{view_name}Trait"), view_name.span());

    let named_fields = match &mut view_struct.fields {
        Fields::Named(f) => &mut f.named,
        _ => {
            return syn::Error::new(
                view_struct.span(),
                "This macro only supports structs with named fields.",
            )
            .into_compile_error()
            .into();
        }
    };

    // Helper to identify String types
    let is_string = |ty: &Type| matches!(ty, Type::Path(tp) if tp.path.segments.last().is_some_and(|s| s.ident == "String"));

    let mut trait_methods = Vec::new();
    let mut impl_methods = Vec::new();

    for f in named_fields.iter_mut() {
        let name = f.ident.as_ref().unwrap();
        let ty = &f.ty; // This is now the *target* type, e.g., `Vec<&str>`

        match get_transform_attribute(&f.attrs) {
            // Case 1: The attribute `#[transform(...)]` was found.
            Ok(Some(transform_attr)) => {
                let transform_fn = &transform_attr.transform_fn;
                let error_type = &transform_attr.error_type;

                // Construct the `Result<SuccessType, ErrorType>` signature.
                // The success type `ty` comes from the field definition itself
                let return_type = quote! { Result<#ty, #error_type> };

                trait_methods
                    .push(quote! { fn #name(&self) -> #return_type; });
                impl_methods.push(quote! { fn #name(&self) -> #return_type { #transform_fn(&self.#name) } });
            }
            // Case 2: No attribute found, use the default logic.
            Ok(None) => {
                // Check if it should return a copy
                if is_known_copy_type(ty) || has_copy_attribute(&f.attrs) {
                    // Generate a getter that returns by value.
                    trait_methods.push(quote! { fn #name(&self) -> #ty; });
                    impl_methods.push(
                        quote! { fn #name(&self) -> #ty { self.#name } },
                    );
                } else if is_string(ty) {
                    // Check if the target type is `String` and return `&str` if it is
                    trait_methods.push(quote! { fn #name(&self) -> &str; });
                    impl_methods.push(
                        quote! { fn #name(&self) -> &str { &self.#name } },
                    );
                } else {
                    // Default behavior: return a reference to the field.
                    trait_methods.push(quote! { fn #name(&self) -> &#ty; });
                    impl_methods.push(
                        quote! { fn #name(&self) -> &#ty { &self.#name } },
                    );
                }
            }
            // Case 3: Attribute was malformed.
            Err(e) => return e.into_compile_error().into(),
        }
        // After processing, remove our helper attribute so the compiler doesn't see it.
        f.attrs.retain(|attr| !attr.path().is_ident("transform"));
    }

    // Output the generated view struct, Trait, and implementation
    let expanded = quote! {
        pub trait #trait_ident {
            #(#trait_methods)*
        }

        impl #trait_ident for #main_struct_ident {
            #(#impl_methods)*
        }
    };

    TokenStream::from(expanded)
}
