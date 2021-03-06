mod statement;

use std::marker::PhantomData;
use std::{collections::HashMap, fmt};

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json;
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Effect {
    Allow,
    Deny,
}

impl Default for Effect {
    fn default() -> Self {
        Effect::Deny
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
struct Principal {
    #[serde(deserialize_with = "option_string_or_seq_strings", rename = "AWS")]
    aws: Option<Vec<String>>,
    #[serde(deserialize_with = "option_string_or_seq_strings")]
    federated: Option<Vec<String>>,
    #[serde(deserialize_with = "option_string_or_seq_strings")]
    service: Option<Vec<String>>,
    #[serde(deserialize_with = "option_string_or_seq_strings")]
    canonical_user: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    #[serde(default, deserialize_with = "option_string_or_seq_strings")]
    action: Option<Vec<String>>,
    #[serde(default, deserialize_with = "option_condition_map")]
    condition: Option<HashMap<String, HashMap<String, Vec<String>>>>,
    effect: Effect,
    #[serde(default, deserialize_with = "option_string_or_seq_strings")]
    not_action: Option<Vec<String>>,
    #[serde(default, deserialize_with = "option_string_or_principal")]
    not_principal: Option<Principal>,
    #[serde(default, deserialize_with = "option_string_or_seq_strings")]
    not_resource: Option<Vec<String>>,
    #[serde(default, deserialize_with = "option_string_or_principal")]
    principal: Option<Principal>,
    #[serde(default, deserialize_with = "option_string_or_seq_strings")]
    resource: Option<Vec<String>>,
    sid: Option<String>,
}

impl Statement {
    pub fn from_str(policy_json: &str) -> Result<Statement, serde_json::Error> {
        serde_json::from_str::<Statement>(policy_json)
    }
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    id: Option<String>,
    #[serde(deserialize_with = "statement_or_seq_statement")]
    statement: Vec<Statement>,
    version: Option<String>,
}

impl Policy {
    pub fn from_str(policy_json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str::<Policy>(policy_json)
    }
}

fn statement_or_seq_statement<'de, D>(deserializer: D) -> Result<Vec<Statement>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StatementOrStatements(PhantomData<Vec<Statement>>);

    impl<'de> de::Visitor<'de> for StatementOrStatements {
        type Value = Vec<Statement>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("statement or list of statements")
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
                .map(|statement| vec![statement])
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(StatementOrStatements(PhantomData))
}

fn string_or_seq_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrStrings(PhantomData<Vec<String>>);

    impl<'de> de::Visitor<'de> for StringOrStrings {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut res: Vec<String> =
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
            res = res.into_iter().map(|item| item.to_lowercase()).collect();
            res.sort();
            Ok(res)
        }
    }

    deserializer.deserialize_any(StringOrStrings(PhantomData))
}

fn option_string_or_seq_strings<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "string_or_seq_strings")] Vec<String>);

    let v = Option::deserialize(deserializer)?;
    Ok(v.map(|Wrapper(a)| a))
}

fn string_or_principal<'de, D>(deserializer: D) -> Result<Principal, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrPrincipal(PhantomData<Principal>);

    impl<'de> de::Visitor<'de> for StringOrPrincipal {
        type Value = Principal;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or principal object")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Principal {
                aws: Some(vec![value.to_owned()]),
                ..Default::default()
            })
        }

        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            Deserialize::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(StringOrPrincipal(PhantomData))
}

fn option_string_or_principal<'de, D>(deserializer: D) -> Result<Option<Principal>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "string_or_principal")] Principal);

    let v = Option::deserialize(deserializer)?;
    Ok(v.map(|Wrapper(a)| a))
}

fn condition_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, HashMap<String, Vec<String>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let temp_map: HashMap<String, HashMap<String, serde_json::Value>> =
        HashMap::deserialize(deserializer)?;

    let mut map: HashMap<String, HashMap<String, Vec<String>>> =
        HashMap::with_capacity(temp_map.len());

    for (condition_type, inner_temp_map) in temp_map {
        let mut inner_map: HashMap<String, Vec<String>> =
            HashMap::with_capacity(inner_temp_map.len());
        for (condition_key, value) in inner_temp_map {
            let parsed = match value {
                serde_json::Value::Array(seq) => seq
                    .into_iter()
                    .map(|v| value_to_string(v).map_err(serde::de::Error::custom))
                    .collect::<Result<Vec<String>, _>>(),

                _ => {
                    let parsed = value_to_string(value).map_err(serde::de::Error::custom)?;
                    Ok(vec![parsed])
                }
            };
            inner_map.insert(condition_key, parsed?);
        }
        map.insert(condition_type, inner_map);
    }

    Ok(map)
}

fn value_to_string(value: serde_json::Value) -> Result<String, serde::de::value::Error> {
    match value {
        serde_json::Value::String(v) => Ok(v),
        serde_json::Value::Bool(v) => Ok(v.to_string()),
        serde_json::Value::Number(v) => Ok(v.to_string()),
        _ => Err(serde::de::Error::custom(
            "unexpected value, expected string, bool or number",
        )),
    }
}

fn option_condition_map<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<String, HashMap<String, Vec<String>>>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(
        #[serde(deserialize_with = "condition_map")] HashMap<String, HashMap<String, Vec<String>>>,
    );

    let v = Option::deserialize(deserializer)?;
    Ok(v.map(|Wrapper(a)| a))
}

#[cfg(test)]
mod tests {

    use super::*;

    macro_rules! condition {
        ($op: expr, $key: expr, $val: expr) => {{
            let mut inner = ::std::collections::HashMap::new();
            inner.insert($key, $val);
            let mut map = ::std::collections::HashMap::new();
            map.insert($op, inner);
            map
        }};
    }

    #[test]
    fn version_serialize_deserialize() {
        let original = r#"{"Statement":[],"Version":"2008-10-17"}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(deserialized.version, Some(String::from("2008-10-17")));
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn id_serialize_deserialize() {
        let original = r#"{"Id":"test_id","Statement":[]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(deserialized.id, Some(String::from("test_id")));
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn statement_serialize_deserialize() {
        let original = r#"{"Statement":{"Effect":"Deny"}}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(deserialized.statement, vec![Statement::default()],);
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, r#"{"Statement":[{"Effect":"Deny"}]}"#);
    }

    #[test]
    fn statements_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(deserialized.statement, vec![Statement::default()],);
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn action_serialize_deserialize() {
        let original = r#"{"Statement":[{"Action":"*","Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                action: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Action":["*"],"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn actions_serialize_deserialize() {
        let original = r#"{"Statement":[{"Action":["*"],"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                action: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn not_action_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotAction":"*"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_action: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Effect":"Deny","NotAction":["*"]}]}"#
        );
    }

    #[test]
    fn not_actions_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotAction":["*"]}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_action: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn not_principal_star_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotPrincipal":"*"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_principal: Some(Principal {
                    aws: Some(vec![String::from("*")]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":["*"]}}]}"#
        );
    }

    #[test]
    fn not_principal_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":["aws"],"Federated":["federated"],"Service":["service"],"CanonicalUser":["canonical_user"]}}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_principal: Some(Principal {
                    aws: Some(vec![String::from("aws")]),
                    federated: Some(vec![String::from("federated")]),
                    service: Some(vec![String::from("service")]),
                    canonical_user: Some(vec![String::from("canonical_user")]),
                }),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn not_resource_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotResource":"*"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_resource: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Effect":"Deny","NotResource":["*"]}]}"#
        );
    }

    #[test]
    fn not_resources_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","NotResource":["*"]}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                not_resource: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn resource_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","Resource":"*"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                resource: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Effect":"Deny","Resource":["*"]}]}"#
        );
    }

    #[test]
    fn resources_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","Resource":["*"]}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                resource: Some(vec![String::from("*")]),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn principal_star_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","Principal":"*"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                principal: Some(Principal {
                    aws: Some(vec![String::from("*")]),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Effect":"Deny","Principal":{"AWS":["*"]}}]}"#
        );
    }

    #[test]
    fn principal_serialize_deserialize() {
        let original = r#"{"Statement":[{"Effect":"Deny","Principal":{"AWS":["aws"],"Federated":["federated"],"Service":["service"],"CanonicalUser":["canonical_user"]}}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                principal: Some(Principal {
                    aws: Some(vec![String::from("aws")]),
                    federated: Some(vec![String::from("federated")]),
                    service: Some(vec![String::from("service")]),
                    canonical_user: Some(vec![String::from("canonical_user")]),
                }),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, original);
    }

    #[test]
    fn condition_string_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":"I'm a string"}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["I'm a string".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["I'm a string"]}},"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn condition_bool_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":true}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["true".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["true"]}},"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn condition_number_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":10}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["10".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["10"]}},"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn condition_string_array_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["string"]}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["string".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["string"]}},"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn condition_bool_array_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":[true]}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["true".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["true"]}},"Effect":"Deny"}]}"#
        );
    }

    #[test]
    fn condition_number_array_value_serialize_deserialize() {
        let original = r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":[33.3]}},"Effect":"Deny"}]}"#;
        let deserialized = Policy::from_str(original).unwrap();
        let condition = condition!(
            "NumericLessThanEquals".to_string(),
            "s3:max-keys".to_string(),
            vec!["33.3".to_string()]
        );
        assert_eq!(
            deserialized.statement,
            vec![Statement {
                condition: Some(condition),
                ..Default::default()
            }],
        );
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(
            serialized,
            r#"{"Statement":[{"Condition":{"NumericLessThanEquals":{"s3:max-keys":["33.3"]}},"Effect":"Deny"}]}"#
        );
    }
}
