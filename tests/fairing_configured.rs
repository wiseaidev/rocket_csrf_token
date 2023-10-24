#[macro_use]
extern crate rocket;

use base64::{engine::general_purpose, Engine as _};
const COOKIE_NAME: &str = "foobar";
const COOKIE_LEN: usize = 64;

fn client() -> rocket::local::blocking::Client {
    rocket::local::blocking::Client::tracked(rocket()).unwrap()
}

fn rocket() -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(rocket_csrf_token::Fairing::new(
            rocket_csrf_token::CsrfConfig::default()
                .with_cookie_name(COOKIE_NAME)
                .with_cookie_len(COOKIE_LEN)
                .with_lifetime(rocket::time::Duration::days(3)),
        ))
        .mount("/", routes![index])
}

#[get("/")]
fn index() {}

#[test]
fn add_csrf_token_to_cookies() {
    general_purpose::STANDARD
        .decode(
            client()
                .get("/")
                .dispatch()
                .cookies()
                .iter()
                .find(|cookie| cookie.name() == COOKIE_NAME)
                .unwrap()
                .value(),
        )
        .unwrap();
}
