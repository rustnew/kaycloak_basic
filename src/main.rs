use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    name: String,
    roles: Vec<String>,
    exp: usize,
}

async fn protected_route(req: HttpRequest) -> impl Responder {
    // Extraire le token du header d'autorisation
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => header.to_str().unwrap_or_default(),
        None => return HttpResponse::Unauthorized().finish(),
    };
    
    // Format "Bearer <token>"
    let token = auth_header.trim_start_matches("Bearer ").trim();
    
    // Valider le token
    let public_key = std::fs::read_to_string("public_key.pem").unwrap();
    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    
    match decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(public_key.as_bytes()).unwrap(),
        &validation,
    ) {
        Ok(token_data) => {
            // Vérifier les rôles si nécessaire
            if token_data.claims.roles.contains(&"admin".to_string()) {
                HttpResponse::Ok().body("Bienvenue, admin!")
            } else {
                HttpResponse::Forbidden().body("Accès refusé")
            }
        }
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/api/protected", web::get().to(protected_route))
    })
    .bind("127.0.0.1:8088")?
    .run()
    .await
}