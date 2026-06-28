//! End-to-end test of the Kubernetes API proxy loop without a real cluster.
//!
//! A mock apiserver (plain HTTP) stands in for the upstream. The proxy
//! TLS-terminates the test client, gates each request against the shipped
//! example policy, redacts Secret reads, denies interactive subresources, and
//! re-originates allowed requests to the mock. The client trusts only the
//! proxy's ephemeral CA and connects over TLS, exactly as a brokered client
//! would.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};

use guard::proxy::{ApiPolicy, KubeProxy, ProxyTls, Upstream};

/// Mock apiserver: returns a Secret (with data), a ConfigMap (with data), or a
/// generic OK for everything else. Records nothing; the proxy is what we test.
async fn mock_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let body: Value = if path.contains("/secrets/") {
        json!({
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {"name": "db", "namespace": "dev"},
            "type": "Opaque",
            "data": {"password": "c2VjcmV0"}
        })
    } else if path.contains("/configmaps/") {
        json!({
            "kind": "ConfigMap",
            "apiVersion": "v1",
            "metadata": {"name": "cm", "namespace": "dev"},
            "data": {"key": "value"}
        })
    } else {
        json!({"kind": "Status", "apiVersion": "v1", "status": "Success"})
    };
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap())
}

async fn spawn_mock_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(mock_handler))
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_gates_redacts_and_forwards() {
    // Upstream: the mock apiserver over plain HTTP (no creds needed).
    let mock_base = spawn_mock_upstream().await;
    let kubeconfig = format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: ctx\nclusters:\n  - name: c\n    cluster: {{server: \"{mock_base}\"}}\ncontexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\nusers:\n  - name: u\n    user: {{}}\n"
    );
    let upstream = Upstream::from_kubeconfig_str(&kubeconfig, None).expect("upstream");

    // Proxy: ephemeral CA, shipped example policy.
    let tls = ProxyTls::generate().expect("tls");
    let ca_pem = tls.ca_pem().to_string();
    let policy = ApiPolicy::from_yaml(include_str!("../examples/api-policy.yaml")).expect("policy");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy = Arc::new(KubeProxy::new(listen, tls, upstream, policy, None));

    // The brokered config must point at the proxy and carry no credential.
    let brokered = proxy.brokered_kubeconfig();
    guard::proxy::validate_brokered_kubeconfig(&brokered).expect("brokered config credential-free");
    assert!(brokered.contains(&format!("https://127.0.0.1:{port}")));

    tokio::spawn(proxy.clone().serve());
    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("https://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    // 1. Reading a Secret is allowed but its values are redacted.
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/secrets/db"))
        .send()
        .await
        .expect("secret read");
    assert_eq!(resp.status(), 200, "secret read should be allowed");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["metadata"]["name"], "db", "metadata survives");
    assert!(v.get("data").is_none(), "Secret data must be redacted");

    // 2. A ConfigMap read passes through unredacted (not a Secret).
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/configmaps/cm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["data"]["key"], "value", "ConfigMap data is not redacted");

    // 3. A delete is held for operator approval -> 403, apiserver never hit.
    let resp = client
        .delete(format!("{base}/api/v1/namespaces/dev/pods/web-0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "delete should be held");
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["kind"], "Status");
    assert!(v["message"]
        .as_str()
        .unwrap()
        .contains("held for operator approval"));

    // 4. An interactive subresource is denied outright.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods/web-0/exec"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "exec must be denied");
    let v: Value = resp.json().await.unwrap();
    assert!(v["message"].as_str().unwrap().contains("exec"));

    // 5. A write in a production namespace falls to default-deny.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/prod/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "prod write should be denied");

    // 6. A write in a non-production namespace is allowed and forwarded.
    let resp = client
        .post(format!("{base}/api/v1/namespaces/dev/pods"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "dev write should be forwarded to upstream"
    );

    // 7. Watching Secret values is denied (the stream cannot be redacted yet).
    let resp = client
        .get(format!("{base}/api/v1/namespaces/dev/secrets?watch=true"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "secret watch must be denied");
}
