// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Removes the schema `format`s the Kubernetes apiserver does not recognise from a CRD.
//!
//! `schemars` names Rust's unsigned integers `uint8` to `uint64`. Kubernetes knows none
//! of them: it drops them from the stored schema, so they validate nothing, and warns on
//! apply (`unrecognized format "uint64"`). The bounds that matter (`minimum: 0`,
//! `maximum`) are separate keywords and stay. The keep rules mirror
//! `pkg/apiserver/validation/formats.go` in apiextensions-apiserver.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
    CustomResourceDefinition, JSONSchemaProps, JSONSchemaPropsOrArray, JSONSchemaPropsOrBool,
    JSONSchemaPropsOrStringArray,
};

/// Integer formats the apiserver keeps (`type: integer`).
const INTEGER_FORMATS: [&str; 2] = ["int32", "int64"];

/// Number formats the apiserver keeps (`type: number`).
const NUMBER_FORMATS: [&str; 2] = ["float", "double"];

/// String formats the apiserver keeps, without dashes: it compares formats with their
/// dashes removed, so `date-time` matches `datetime` (the 1.0 set plus the 1.34 names).
const STRING_FORMATS: [&str; 26] = [
    "bsonobjectid",
    "uri",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "cidr",
    "mac",
    "uuid",
    "uuid3",
    "uuid4",
    "uuid5",
    "isbn",
    "isbn10",
    "isbn13",
    "creditcard",
    "ssn",
    "hexcolor",
    "rgbcolor",
    "byte",
    "password",
    "date",
    "duration",
    "datetime",
    "k8sshortname",
    "k8slongname",
];

/// Remove every `format` the apiserver does not recognise from each version's schema.
pub fn strip_unsupported_formats(crd: &mut CustomResourceDefinition) {
    for version in &mut crd.spec.versions {
        if let Some(root) = version
            .schema
            .as_mut()
            .and_then(|s| s.open_api_v3_schema.as_mut())
        {
            strip_unsupported_schema_formats(root);
        }
    }
}

/// Whether the apiserver keeps `format` on a `type: string` (or untyped) schema. Dashes
/// are ignored, as the apiserver ignores them.
#[must_use]
pub fn is_supported_string_format(format: &str) -> bool {
    STRING_FORMATS.contains(&format.replace('-', "").as_str())
}

/// Whether the apiserver keeps `format` on a schema of type `type_`.
#[must_use]
pub fn is_supported_format(type_: Option<&str>, format: &str) -> bool {
    match type_ {
        Some("integer") => INTEGER_FORMATS.contains(&format),
        Some("number") => NUMBER_FORMATS.contains(&format),
        None | Some("string") => is_supported_string_format(format),
        Some(_) => false,
    }
}

/// [`strip_unsupported_formats`] for one schema and everything under it: properties,
/// items, additional properties and items, the combinators, pattern properties,
/// definitions and schema dependencies.
pub fn strip_unsupported_schema_formats(schema: &mut JSONSchemaProps) {
    if let Some(format) = schema.format.as_deref()
        && !is_supported_format(schema.type_.as_deref(), format)
    {
        schema.format = None;
    }

    let maps = [
        schema.properties.as_mut(),
        schema.pattern_properties.as_mut(),
        schema.definitions.as_mut(),
    ];
    for child in maps.into_iter().flatten().flat_map(|m| m.values_mut()) {
        strip_unsupported_schema_formats(child);
    }
    let lists = [
        schema.all_of.as_mut(),
        schema.any_of.as_mut(),
        schema.one_of.as_mut(),
    ];
    for child in lists.into_iter().flatten().flat_map(|v| v.iter_mut()) {
        strip_unsupported_schema_formats(child);
    }
    match schema.items.as_mut() {
        Some(JSONSchemaPropsOrArray::Schema(child)) => strip_unsupported_schema_formats(child),
        Some(JSONSchemaPropsOrArray::Schemas(children)) => {
            children
                .iter_mut()
                .for_each(strip_unsupported_schema_formats);
        }
        None => {}
    }
    for child in [
        schema.additional_properties.as_mut(),
        schema.additional_items.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        if let JSONSchemaPropsOrBool::Schema(child) = child {
            strip_unsupported_schema_formats(child);
        }
    }
    if let Some(child) = schema.not.as_mut() {
        strip_unsupported_schema_formats(child);
    }
    for dependency in schema.dependencies.iter_mut().flat_map(|m| m.values_mut()) {
        if let JSONSchemaPropsOrStringArray::Schema(child) = dependency {
            strip_unsupported_schema_formats(child);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
        CustomResourceDefinitionSpec, CustomResourceDefinitionVersion, CustomResourceValidation,
    };

    use super::*;

    fn typed(type_: &str, format: &str) -> JSONSchemaProps {
        JSONSchemaProps {
            type_: Some(type_.into()),
            format: Some(format.into()),
            ..JSONSchemaProps::default()
        }
    }

    fn kept(type_: &str, format: &str) -> bool {
        let mut s = typed(type_, format);
        strip_unsupported_schema_formats(&mut s);
        s.format.is_some()
    }

    #[test]
    fn integer_formats_keep_only_int32_and_int64() {
        assert!(kept("integer", "int32"));
        assert!(kept("integer", "int64"));
        for f in ["uint8", "uint16", "uint32", "uint64", "int8", "double"] {
            assert!(!kept("integer", f), "{f} should go");
        }
    }

    #[test]
    fn number_formats_keep_only_float_and_double() {
        assert!(kept("number", "float"));
        assert!(kept("number", "double"));
        assert!(!kept("number", "int64"));
    }

    #[test]
    fn string_formats_keep_the_kubernetes_set() {
        for f in [
            "date-time",
            "datetime",
            "uri",
            "k8s-short-name",
            "byte",
            "uuid4",
        ] {
            assert!(kept("string", f), "{f} should stay");
        }
        assert!(!kept("string", "json"));
        assert!(!kept("string", "uint64"));
        let mut untyped = JSONSchemaProps {
            format: Some("date-time".into()),
            ..JSONSchemaProps::default()
        };
        strip_unsupported_schema_formats(&mut untyped);
        assert_eq!(untyped.format.as_deref(), Some("date-time"));
    }

    #[test]
    fn other_types_lose_any_format() {
        assert!(!kept("boolean", "int32"));
        assert!(!kept("object", "date-time"));
        assert!(!kept("array", "uri"));
    }

    #[test]
    fn nested_schemas_are_cleaned_and_a_property_named_format_stays() {
        let mut props = BTreeMap::new();
        props.insert("format".to_owned(), typed("integer", "uint32"));
        props.insert(
            "list".to_owned(),
            JSONSchemaProps {
                type_: Some("array".into()),
                items: Some(JSONSchemaPropsOrArray::Schema(Box::new(typed(
                    "integer", "uint64",
                )))),
                ..JSONSchemaProps::default()
            },
        );
        props.insert(
            "map".to_owned(),
            JSONSchemaProps {
                type_: Some("object".into()),
                additional_properties: Some(JSONSchemaPropsOrBool::Schema(Box::new(typed(
                    "integer", "uint16",
                )))),
                ..JSONSchemaProps::default()
            },
        );
        props.insert(
            "either".to_owned(),
            JSONSchemaProps {
                any_of: Some(vec![
                    typed("integer", "uint8"),
                    typed("string", "date-time"),
                ]),
                ..JSONSchemaProps::default()
            },
        );
        let mut crd = CustomResourceDefinition {
            spec: CustomResourceDefinitionSpec {
                versions: vec![CustomResourceDefinitionVersion {
                    schema: Some(CustomResourceValidation {
                        open_api_v3_schema: Some(JSONSchemaProps {
                            type_: Some("object".into()),
                            properties: Some(props),
                            ..JSONSchemaProps::default()
                        }),
                    }),
                    ..CustomResourceDefinitionVersion::default()
                }],
                ..CustomResourceDefinitionSpec::default()
            },
            ..CustomResourceDefinition::default()
        };
        strip_unsupported_formats(&mut crd);
        let root = crd.spec.versions[0]
            .schema
            .as_ref()
            .and_then(|s| s.open_api_v3_schema.as_ref())
            .unwrap();
        let props = root.properties.as_ref().unwrap();
        assert!(props.contains_key("format"), "the property itself stays");
        assert_eq!(props["format"].format, None);
        let Some(JSONSchemaPropsOrArray::Schema(item)) = &props["list"].items else {
            panic!("items")
        };
        assert_eq!(item.format, None);
        let Some(JSONSchemaPropsOrBool::Schema(value)) = &props["map"].additional_properties else {
            panic!("additionalProperties")
        };
        assert_eq!(value.format, None);
        let any = props["either"].any_of.as_ref().unwrap();
        assert_eq!(any[0].format, None);
        assert_eq!(any[1].format.as_deref(), Some("date-time"));
    }
}
