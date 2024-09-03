use libyang::Entry;
use serde_json::Value;
use std::fs::File;
use std::io::prelude::*;
use std::rc::Rc;

pub fn json_read(e: Rc<Entry>) {
    println!("Read JSON configuration");
    let mut file = File::open("/Users/kunihiro/z.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    let json: Value = serde_json::from_str(contents.as_str()).unwrap();
    json_to_list(e, Vec::new(), &json);

    println!("{}", json);
}

pub fn json_to_list(entry: Rc<Entry>, p: Vec<String>, v: &Value) {
    match v {
        Value::Null => {
            println!("{}", p.join(" "));
        }
        Value::Bool(v) => {
            println!("{} {}", p.join(" "), v);
        }
        Value::Number(v) => {
            println!("{} {}", p.join(" "), v);
        }
        Value::String(v) => {
            println!("{} {}", p.join(" "), v);
        }
        Value::Array(vec) => {
            for v in vec.iter() {
                let p = p.clone();
                json_to_list(entry.clone(), p, v);
            }
        }
        Value::Object(map) => {
            let mut p = p.clone();
            if !entry.key.is_empty() {
                if let Some(value) = map.get(&entry.key[0]) {
                    p.push(value_without_quotes(&value));
                    println!("{}", p.join(" "));
                } else {
                    println!("Not found key {}", entry.key[0]);
                    return;
                }
            }
            for (key, value) in map.iter() {
                if !entry.key.is_empty() && key == &entry.key[0] {
                    continue;
                }
                match entry_dir(entry.clone(), key) {
                    Some(entry) => {
                        let mut p = p.clone();
                        p.push(key.clone());
                        json_to_list(entry.clone(), p, &value);
                    }
                    None => {
                        println!("Not found key {}", key);
                        return;
                    }
                }
            }
        }
    }
}

fn value_without_quotes(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn entry_dir(entry: Rc<Entry>, name: &String) -> Option<Rc<Entry>> {
    for e in entry.dir.borrow().iter() {
        if e.name == *name {
            return Some(e.clone());
        }
    }
    None
}
