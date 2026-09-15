use krypt_core::crypto::KdfParams;
use krypt_core::export::{self, ExportPayload};
use krypt_core::model::{ApiKey, DomainRule, Item, ItemData, ItemType, Login, Service};
use krypt_core::secret::Secret;
use krypt_core::totp::TotpAlgorithm;
use krypt_import::{Error, Parsed, Plan, Source, host_of, needs_password, parse, plan, site_of};

const FAST: KdfParams = KdfParams {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

const CHROME: &str = "name,url,username,password,note
github.com,https://github.com/login,octo,pw-1,
accounts.google.com,https://accounts.google.com/signin,me@gmail.com,pw-2,
mail.google.com,https://mail.google.com/,me@gmail.com,pw-3,work mail
foo.github.io,https://foo.github.io/,foo,pw-4,
";

fn read(text: &str) -> Parsed {
    parse(text.as_bytes(), None).unwrap()
}

fn login(item: &Item) -> &Login {
    match &item.data {
        ItemData::Login(login) => login,
        other => panic!("expected a login, got {:?}", other.item_type()),
    }
}

fn new_service_names(plan: &Plan) -> Vec<&str> {
    let mut names: Vec<&str> = plan
        .new_services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    names.sort_unstable();
    names
}

fn by_password<'a>(plan: &'a Plan, password: &str) -> &'a Item {
    plan.items
        .iter()
        .find(|item| login(item).password.expose() == password)
        .unwrap()
}

#[test]
fn a_browser_export_is_grouped_by_site() {
    let parsed = read(CHROME);
    assert_eq!(parsed.source, Source::Chromium);
    assert_eq!(parsed.candidates.len(), 4);

    let plan = plan(parsed, &[], &[]);
    assert_eq!(new_service_names(&plan), ["Foo", "Github", "Google"]);
    assert_eq!(plan.items.len(), 4);
    assert!(plan.items.iter().all(|item| item.label.is_empty()));

    let google = plan
        .new_services
        .iter()
        .find(|service| service.name == "Google")
        .unwrap();
    assert_eq!(google.domains, [DomainRule::new("google.com")]);
    let mail = by_password(&plan, "pw-3");
    assert_eq!(mail.service_id, Some(google.id));
    assert_eq!(login(mail).email.as_deref(), Some("me@gmail.com"));
    assert_eq!(login(mail).username, None);
    assert_eq!(login(mail).urls, ["https://mail.google.com/"]);
    assert_eq!(mail.notes.expose(), "work mail");

    let github = by_password(&plan, "pw-1");
    assert!(
        login(github).urls.is_empty(),
        "the site's own address adds nothing"
    );
}

#[test]
fn existing_services_are_reused_and_duplicates_left_out() {
    let mut github = Service::new("GitHub");
    github.domains = vec![DomainRule::new("github.com")];
    let mut existing = Item::new(
        ItemData::Login(Login {
            username: Some("Octo".into()),
            password: Secret::new("pw-1"),
            ..Login::default()
        }),
        1,
    );
    existing.service_id = Some(github.id);

    let twice = "github.com,https://www.github.com/,octo-work,pw-5,\n";
    let plan = plan(
        read(&format!("{CHROME}{twice}{twice}")),
        &[github.clone()],
        &[existing],
    );
    assert_eq!(
        plan.duplicates, 2,
        "one is already in the vault, one is twice in the file"
    );
    assert_eq!(plan.items.len(), 4);
    assert_eq!(new_service_names(&plan), ["Foo", "Google"]);
    assert_eq!(plan.existing_services, ["GitHub"]);
    let work = by_password(&plan, "pw-5");
    assert_eq!(work.service_id, Some(github.id));
    assert!(login(work).urls.is_empty());
}

#[test]
fn a_new_service_takes_the_most_common_name() {
    let plan = plan(
        read(
            "name,url,username,password\n\
             GitHub,https://github.com,octo,a\n\
             GitHub,https://github.com,octo2,b\n\
             GitHub Work,https://github.com,octo3,c\n",
        ),
        &[],
        &[],
    );
    assert_eq!(new_service_names(&plan), ["GitHub"]);
    let labels: Vec<&str> = plan.items.iter().map(|item| item.label.as_str()).collect();
    assert_eq!(labels, ["", "", "GitHub Work"]);
}

#[test]
fn bitwarden_csv_keeps_folders_fields_and_codes() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,1,login,GitHub Work,,\"Recovery email: backup@example.com
PIN: 1234\",0,https://github.com,octo-work,pw-w,otpauth://totp/GitHub:octo?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub
,,note,Server notes,root password is elsewhere,,0,,,,
,,login,Steam,,,0,https://store.steampowered.com,gamer,pw-s,steam://ABCDEF
";
    let parsed = read(csv);
    assert_eq!(parsed.source, Source::Bitwarden);
    let [work, note, steam] = parsed.candidates.as_slice() else {
        panic!("{} candidates", parsed.candidates.len())
    };

    assert!(work.item.favorite);
    assert_eq!(work.item.tags, ["Work"]);
    let fields: Vec<(&str, &str, bool)> = work
        .item
        .custom_fields
        .iter()
        .map(|field| (field.name.as_str(), field.value.expose(), field.hidden))
        .collect();
    assert_eq!(
        fields,
        [
            ("Recovery email", "backup@example.com", false),
            ("PIN", "1234", true)
        ]
    );
    let totp = login(&work.item).totp.as_ref().unwrap();
    assert_eq!(totp.issuer.as_deref(), Some("GitHub"));

    let ItemData::Note(text) = &note.item.data else {
        panic!("not a note")
    };
    assert_eq!(text.text.expose(), "root password is elsewhere");

    assert!(login(&steam.item).totp.is_none());
    assert_eq!(steam.item.custom_fields[0].name, "TOTP");
    assert_eq!(steam.item.custom_fields[0].value.expose(), "steam://ABCDEF");
}

#[test]
fn csv_exports_of_many_apps_are_recognized() {
    let cases = [
        (
            "url,username,password,totp,extra,name,grouping,fav\nhttps://x.com,u,p,,,X,Social,0\nhttp://sn,,,,secret note text,Wifi,,0\n",
            Source::LastPass,
        ),
        (
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://x.com,u,p,,https://x.com,{abc},1,1,1\n",
            Source::Firefox,
        ),
        (
            "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nX,https://x.com,u,p,,false,false,a;b,\n",
            Source::OnePassword,
        ),
        (
            "Title,URL,Username,Password,Notes,OTPAuth\nX,https://x.com,u,p,,\n",
            Source::Safari,
        ),
        (
            "Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created\nRoot/Web,X,u,p,https://x.com,,,0,2024,2024\n",
            Source::KeePass,
        ),
        (
            "username,username2,username3,title,password,note,url,category,otpSecret\nu,alt,,X,p,,https://x.com,Web,\n",
            Source::Dashlane,
        ),
        (
            "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\nlogin,X,https://x.com,u@x.com,,p,,,1,1,Personal\n",
            Source::ProtonPass,
        ),
        (
            concat!(
                "name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,",
                "folder,full_name,phone_number,email,address1,address2,city,country,state,type\n",
                "X,https://x.com,u,p",
                ",,,,",
                ",,,,",
                ",,,,",
                ",,,,",
                "password\n"
            ),
            Source::NordPass,
        ),
        (
            "Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\nX,https://x.com,https://x.com,u,p,,/Web,\n",
            Source::RoboForm,
        ),
    ];
    for (csv, source) in cases {
        let parsed = read(csv);
        assert_eq!(parsed.source, source, "{csv}");
        let first = &parsed.candidates[0];
        let account = login(&first.item);
        assert_eq!(account.password.expose(), "p", "{csv}");
        assert!(
            account.username.as_deref() == Some("u") || account.email.as_deref() == Some("u@x.com"),
            "{csv}"
        );
        assert_eq!(first.url.as_deref(), Some("https://x.com"), "{csv}");
    }

    let lastpass = read(cases[0].0);
    let ItemData::Note(note) = &lastpass.candidates[1].item.data else {
        panic!("the http://sn row is a secure note")
    };
    assert_eq!(note.text.expose(), "secret note text");

    let dashlane = read(cases[5].0);
    let extra = &dashlane.candidates[0].item.custom_fields[0];
    assert_eq!(
        (extra.name.as_str(), extra.value.expose()),
        ("username2", "alt")
    );
    assert_eq!(dashlane.candidates[0].item.tags, ["Web"]);
}

#[test]
fn nordpass_cards_and_identities_become_their_own_types() {
    let csv = concat!(
        "name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,",
        "folder,full_name,phone_number,email,address1,address2,city,country,state,type\n",
        "Visa,,,,",
        ",Jane Doe,4111111111111111,123,05/27",
        ",,,,,",
        ",,,,,",
        ",credit_card\n",
        "Me,,,,",
        ",,,,",
        ",10115,",
        ",Jane Doe,+49 30 1234,jane@example.com,Main St 1,Apt 2,Berlin,DE,BE,identity\n",
    );
    let parsed = read(csv);
    let [card, me] = parsed.candidates.as_slice() else {
        panic!("{} candidates", parsed.candidates.len())
    };

    let ItemData::Card(card) = &card.item.data else {
        panic!("not a card")
    };
    assert_eq!(card.holder.as_deref(), Some("Jane Doe"));
    assert_eq!(card.number.expose(), "4111111111111111");
    assert_eq!(card.cvc.as_ref().map(Secret::expose), Some("123"));
    assert_eq!((card.expiry_month, card.expiry_year), (Some(5), Some(2027)));

    let ItemData::Identity(identity) = &me.item.data else {
        panic!("not an identity")
    };
    assert_eq!(identity.full_name, "Jane Doe");
    assert_eq!(identity.email.as_deref(), Some("jane@example.com"));
    assert_eq!(identity.phone.as_deref(), Some("+49 30 1234"));
    let address = identity.address.as_ref().unwrap();
    assert_eq!(address.street.as_deref(), Some("Main St 1, Apt 2"));
    assert_eq!(
        (
            address.postal_code.as_deref(),
            address.city.as_deref(),
            address.region.as_deref(),
            address.country.as_deref()
        ),
        (Some("10115"), Some("Berlin"), Some("BE"), Some("DE"))
    );
}

#[test]
fn semicolons_german_headers_and_old_encodings_are_read() {
    let text =
        "Titel;Benutzername;Passwort;Webseite\nBank;kunde;geheim\u{20ac}1;https://bank.example\n";
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let windows_1252: Vec<u8> = text
        .chars()
        .map(|c| if c == '\u{20ac}' { 0x80 } else { c as u8 })
        .collect();
    let utf8_bom = [&[0xEF, 0xBB, 0xBF][..], text.as_bytes()].concat();

    for bytes in [text.as_bytes().to_vec(), utf16, windows_1252, utf8_bom] {
        let parsed = parse(&bytes, None).unwrap();
        assert_eq!(parsed.source, Source::Csv);
        let first = &parsed.candidates[0];
        assert_eq!(first.name.as_deref(), Some("Bank"));
        assert_eq!(login(&first.item).username.as_deref(), Some("kunde"));
        assert_eq!(login(&first.item).password.expose(), "geheim\u{20ac}1");
    }
}

#[test]
fn bitwarden_json_brings_every_type() {
    let json = r#"{
      "encrypted": false,
      "folders": [{ "id": "f1", "name": "Work" }],
      "items": [
        { "id": "1", "folderId": "f1", "type": 1, "name": "GitHub", "notes": null, "favorite": true,
          "fields": [{ "name": "PIN", "value": "1234", "type": 1 }, { "name": "Plan", "value": "Pro", "type": 0 }],
          "login": { "uris": [{ "match": null, "uri": "https://github.com/login" }, { "uri": "https://gist.github.com" }],
                     "username": "octo", "password": " pw & <more> ", "totp": "GEZDGNBVGY3TQOJQ" } },
        { "id": "2", "type": 2, "name": "Wifi", "notes": "network: home", "secureNote": { "type": 0 } },
        { "id": "3", "type": 3, "name": "Visa", "card": { "cardholderName": "Jane Doe", "brand": "Visa",
          "number": "4111111111111111", "expMonth": "5", "expYear": "2027", "code": "123" } },
        { "id": "4", "type": 4, "name": "Me", "identity": { "firstName": "Jane", "lastName": "Doe",
          "email": "jane@example.com", "address1": "Main St 1", "city": "Berlin", "postalCode": "10115",
          "country": "DE", "passportNumber": "C01X00T47", "company": "ACME" } },
        { "id": "5", "type": 5, "name": "Laptop", "sshKey": { "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
          "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:xyz" } },
        { "id": "6", "type": 99, "name": "From the future" }
      ]
    }"#;
    let parsed = read(json);
    assert_eq!(parsed.source, Source::Bitwarden);
    assert_eq!(parsed.skipped, 1);
    let types: Vec<ItemType> = parsed
        .candidates
        .iter()
        .map(|candidate| candidate.item.item_type())
        .collect();
    assert_eq!(
        types,
        [
            ItemType::Login,
            ItemType::Note,
            ItemType::Card,
            ItemType::Identity,
            ItemType::SshKey
        ]
    );

    let github = &parsed.candidates[0];
    assert_eq!(github.url.as_deref(), Some("https://github.com/login"));
    assert!(github.item.favorite);
    assert_eq!(github.item.tags, ["Work"]);
    let account = login(&github.item);
    assert_eq!(account.urls, ["https://gist.github.com"]);
    assert_eq!(
        account.password.expose(),
        " pw & <more> ",
        "passwords are not trimmed"
    );
    assert!(account.totp.is_some());
    assert!(github.item.custom_fields[0].hidden);
    assert!(!github.item.custom_fields[1].hidden);

    let ItemData::Identity(identity) = &parsed.candidates[3].item.data else {
        panic!("not an identity")
    };
    assert_eq!(identity.full_name, "Jane Doe");
    assert_eq!(identity.documents[0].kind, "passport");
    assert_eq!(parsed.candidates[3].item.custom_fields[0].name, "Company");

    let encrypted = r#"{ "encrypted": true, "passwordProtected": true, "data": "abc" }"#;
    assert_eq!(
        parse(encrypted.as_bytes(), None).unwrap_err(),
        Error::Encrypted
    );
}

#[test]
fn keepass_xml_skips_history_and_the_recycle_bin() {
    let xml = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><DatabaseName>Mine</DatabaseName><RecycleBinUUID>YmluYmluYmluYmluYmluYg==</RecycleBinUUID></Meta>
  <Root>
    <Group>
      <UUID>cm9vdHJvb3Ryb290cm9vdA==</UUID>
      <Name>Mine</Name>
      <Entry>
        <UUID>ZW50cnkxZW50cnkxZW50cg==</UUID>
        <String><Key>Notes</Key><Value /></String>
        <String><Key>Password</Key><Value ProtectInMemory="True">p&amp;w &lt;1&gt;</Value></String>
        <String><Key>Title</Key><Value>Mail</Value></String>
        <String><Key>URL</Key><Value>https://mail.example.com</Value></String>
        <String><Key>UserName</Key><Value>me</Value></String>
        <String><Key>otp</Key><Value>otpauth://totp/Mail:me?secret=GEZDGNBVGY3TQOJQ&amp;period=30</Value></String>
        <String><Key>Recovery PIN</Key><Value ProtectInMemory="True">9876</Value></String>
        <History><Entry><String><Key>Password</Key><Value>old</Value></String></Entry></History>
      </Entry>
      <Group>
        <UUID>d2Vid2Vid2Vid2Vid2ViZA==</UUID>
        <Name>Web</Name>
        <Entry>
          <String><Key>Title</Key><Value>Shop</Value></String>
          <String><Key>UserName</Key><Value>buyer</Value></String>
          <String><Key>Password</Key><Value>s</Value></String>
          <String><Key>TimeOtp-Secret-Base32</Key><Value>GEZDGNBVGY3TQOJQ</Value></String>
          <String><Key>TimeOtp-Length</Key><Value>8</Value></String>
          <String><Key>TimeOtp-Algorithm</Key><Value>HMAC-SHA-256</Value></String>
        </Entry>
      </Group>
      <Group>
        <UUID>YmluYmluYmluYmluYmluYg==</UUID>
        <Name>Recycle Bin</Name>
        <Entry>
          <String><Key>Title</Key><Value>Deleted</Value></String>
          <String><Key>Password</Key><Value>x</Value></String>
        </Entry>
      </Group>
    </Group>
    <DeletedObjects />
  </Root>
</KeePassFile>"#;
    let parsed = read(xml);
    assert_eq!(parsed.source, Source::KeePass);
    assert_eq!(parsed.skipped, 1);
    let [mail, shop] = parsed.candidates.as_slice() else {
        panic!("{} candidates", parsed.candidates.len())
    };

    let account = login(&mail.item);
    assert_eq!(account.password.expose(), "p&w <1>");
    assert_eq!(account.username.as_deref(), Some("me"));
    assert!(account.totp.is_some());
    assert!(mail.item.tags.is_empty());
    let pin = &mail.item.custom_fields[0];
    assert_eq!(
        (pin.name.as_str(), pin.value.expose(), pin.hidden),
        ("Recovery PIN", "9876", true)
    );

    assert_eq!(shop.item.tags, ["Web"]);
    let totp = login(&shop.item).totp.as_ref().unwrap();
    assert_eq!((totp.digits, totp.algorithm), (8, TotpAlgorithm::Sha256));
}

#[test]
fn a_krypt_export_needs_its_password_and_brings_its_services() {
    let mut service = Service::new("Anthropic");
    service.domains = vec![DomainRule::new("anthropic.com")];
    let mut key = Item::new(
        ItemData::ApiKey(ApiKey {
            key: Secret::new("sk-1"),
            ..ApiKey::default()
        }),
        1,
    );
    key.service_id = Some(service.id);
    key.label = "Production".into();
    let payload = ExportPayload {
        exported_at: 1,
        services: vec![service.clone()],
        items: vec![key.clone()],
    };
    let bytes = export::seal(&payload, "Export-Pass-1", FAST).unwrap();

    assert!(needs_password(&bytes));
    assert!(!needs_password(CHROME.as_bytes()));
    assert_eq!(parse(&bytes, None).unwrap_err(), Error::PasswordRequired);
    assert_eq!(
        parse(&bytes, Some("Export-Pass-2")).unwrap_err(),
        Error::Core(krypt_core::Error::Decrypt)
    );

    let parsed = parse(&bytes, Some("Export-Pass-1")).unwrap();
    assert_eq!(parsed.source, Source::Krypt);
    let fresh = plan(parsed, &[], &[]);
    assert_eq!(fresh.new_services, [service.clone()]);
    assert_eq!(fresh.items, [key.clone()]);

    let again = plan(
        parse(&bytes, Some("Export-Pass-1")).unwrap(),
        &[service],
        &[key],
    );
    assert_eq!(
        (
            again.items.len(),
            again.new_services.len(),
            again.duplicates
        ),
        (0, 0, 1)
    );
}

#[test]
fn files_without_known_columns_are_refused() {
    for bytes in [
        &b"just some text\nwithout columns"[..],
        b"<html><body>hi</body></html>",
        br#"{"hello": 1}"#,
        b"",
        b"1,2,3\n4,5,6\n",
    ] {
        assert_eq!(
            parse(bytes, None).unwrap_err(),
            Error::UnknownFormat,
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn hosts_and_sites() {
    assert_eq!(
        host_of("https://Accounts.Google.com:443/x?y").as_deref(),
        Some("accounts.google.com")
    );
    assert_eq!(host_of("github.com/login").as_deref(), Some("github.com"));
    assert_eq!(host_of("androidapp://com.example.app"), None);
    assert_eq!(host_of("http://sn"), None);
    assert_eq!(host_of("My Bank"), None);
    assert_eq!(site_of("mail.google.com"), "google.com");
    assert_eq!(site_of("www.bbc.co.uk"), "bbc.co.uk");
    assert_eq!(site_of("foo.github.io"), "foo.github.io");
    assert_eq!(site_of("192.168.1.10"), "192.168.1.10");
    assert_eq!(site_of("localhost"), "localhost");
}
