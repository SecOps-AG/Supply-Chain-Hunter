// Default: same-origin JSON (the Pages host answers /live/* from the R2 bucket).
// Override dataBase to read from a dedicated data host instead, e.g.
// window.HUNTER_PUBLIC = { dataBase: "https://data.example.com" };
window.HUNTER_PUBLIC = window.HUNTER_PUBLIC || { dataBase: "" };
