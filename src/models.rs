use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct CourseList {
    pub count: u32,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    pub items: Vec<Course>,
    pub limit: u32,
    pub offset: u32,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Course {
    pub id_cursus: u32,
    pub cursus: String,
    pub cursus_korte_naam: String,
}

// Registering for a course requires the entire test details
#[derive(Serialize, Deserialize, Debug)]
pub struct TestList {
    pub id_cursus: u32,
    pub studentnummer: String,
    pub cursus: String,
    pub collegejaar: u32,
    pub cursus_korte_naam: String,
    pub opmerking_cursus: String,
    pub punten: u8,
    pub punteneenheid: String,
    pub coordinerend_onderdeel_oms: String,
    pub faculteit_naam: String,
    pub categorie_omschrijving: String,
    pub cursustype_omschrijving: String,
    pub onderdeel_van: String,
    pub toetsen: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Test {
    pub id_cursus: u32,
    pub id_toets_gelegenheid: u32,
    pub toets: String,
    pub toets_omschrijving: String,
    pub toetsvorm_omschrijving: String,
    pub opmerking_cursus_toets: String,
    pub aanvangsblok: String,
    pub onderwijsvorm: String,
    pub onderwijsvorm_omschrijving: String,
    pub blok: String,
    pub periode_omschrijving: String,
    pub gelegenheid: u8,
    pub beschikbare_plekken: Option<u32>,
    pub toetsdatum: String,
    pub dag: String,
    pub tijd_vanaf: f64,
    pub tijd_tm: f64,
    pub locatie: String,
    pub locatie_x: String,
    pub locatie_y: String,
    pub eerder_voldoende_behaald: String,
    pub voorzieningen: Vec<String>,
}
