use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{StatusCode, HeaderValue};
use axum::response::{IntoResponse, Response, Result};
use axum::routing::{get, post};
use axum::Router;
use schema::{HttpLoadBalancerService, HttpLoadBalancerServiceServersItem};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber;

use crate::schema::HttpRouter;

pub mod schema;

#[derive(Clone)]
struct AppLocation{
    name: String,
    url:  String,
}

#[derive(Clone)]
struct AppState {
    apps: Vec<AppLocation>
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/", get(root)).with_state(AppState {apps: vec![AppLocation{name: String::from("template"), url: String::from("127.0.0.1:4500")}]});

    let addr = std::env::var("SERVER_ADDRESS")
        .unwrap_or(String::from("0.0.0.0:4567"))
        .parse()
        .unwrap();

    info!("starting on: {addr}");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root(State(app_state): State<AppState>) -> Result<Response> {
    info!("got request");
    // let out = String::from("hallo");
    let mut services = HashMap::new();
    let mut routers = HashMap::new();

    for app in app_state.apps {
        let load_balancer = HttpLoadBalancerService {
            health_check: None,
            pass_host_header: true,
            response_forwarding: None,
            servers: vec![HttpLoadBalancerServiceServersItem {
                url: format!("http://{}", app.url),
            }],
            servers_transport: None,
            sticky: None,
        };
        services.insert(
            app.name.clone(),
            schema::HttpService::Variant0 {
                load_balancer: Some(load_balancer),
            },
        );

        let router = HttpRouter{ entry_points: vec![String::from("web")], middlewares: Vec::new(), priority: 0, rule: format!("PathPrefix(`/{}`)", app.name), service: app.name.clone(), tls: None };

        routers.insert(app.name, router);
    }

    let root_http = schema::RootHttp {
        middlewares: HashMap::new(),
        routers,
        services,
    };
    let root = schema::Root {
        http: Some(root_http),
        tcp: None,
        tls: None,
        udp: None,
    };
    let out = serde_json::to_string(&root).unwrap();
    let mut response = out.into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}
