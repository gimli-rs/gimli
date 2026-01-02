const URL: &str = "https://www.unicode.org/Public/UCD/latest/ucd/CaseFolding.txt";

fn main() {
    let output = std::process::Command::new("curl")
        .arg(URL)
        .output()
        .unwrap();
    if !output.status.success() {
        panic!(
            "Failed to run curl to fetch {URL}: stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut pairs = vec![
        // Turkish upper case dotted ’İ’ and lower case dotless ’ı’ are folded
        // to the Latin lower case ’i’.
        (0x130, 'i' as u32),
        (0x131, 'i' as u32),
    ];

    let text = std::str::from_utf8(&output.stdout).unwrap();
    let mut lines = text.lines();
    let version = lines.next().unwrap();
    for line in lines {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split(';').map(str::trim);
        let code = fields.next().unwrap();
        let status = fields.next().unwrap();
        if status != "C" && status != "S" {
            continue;
        }
        let mapping = fields.next().unwrap();
        assert_eq!(fields.next(), Some(""));
        assert_eq!(fields.next(), None);

        let code = u32::from_str_radix(code, 16).unwrap();
        let mapping = u32::from_str_radix(mapping, 16).unwrap();
        // ASCII and Turkish i have special handling.
        if code > 0x7f && code != 0x130 && code != 0x131 {
            pairs.push((code, mapping));
        }
    }

    pairs.sort_by_key(|p| p.0);

    println!("// Generated from {version}");
    println!(
        "static CASE_FOLD_DATA: &[(char, char); {}] = &[",
        pairs.len()
    );
    for (code, mapping) in pairs {
        println!("    ('\\u{{{:x}}}', '\\u{{{:x}}}'),", code, mapping);
    }
    println!("];");
}
