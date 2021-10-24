use serde::{
    de::{value, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::fmt;

#[derive(Serialize, Debug, PartialEq)]
pub struct Action(Vec<String>);

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ActionVisitor)
    }
}

struct ActionVisitor;

impl<'de> Visitor<'de> for ActionVisitor {
    type Value = Action;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string or an array of strings")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Action(vec![v.to_owned()]))
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Deserialize::deserialize(value::SeqAccessDeserializer::new(seq))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    action: Option<Action>,
}

#[cfg(test)]
mod tests {
    use serde_json::from_str;

    use super::*;

    #[test]
    fn version_serialize_deserialize() {
        let original = r#"{"Action":"test"}"#;
        let deserialized: Statement = from_str(original).unwrap();
        assert_eq!(deserialized.action, Some(Action(vec!["test".to_string()])));
        let serialized = serde_json::to_string(&deserialized).unwrap();
        assert_eq!(serialized, r#"{"Action":["test"]}"#);
    }
}
