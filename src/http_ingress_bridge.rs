//! Host side of the `http` transport wire.
//!
//! A native `http`-wire transport calls [`HttpServerRef::serve`] per
//! received request. The call returns at once: the request runs on the
//! host runtime against the gateway's [`HttpIngressServer`], and the answer
//! goes back through the plugin's [`HttpResponderRef`].
//!
//! Lifetimes: the plugin's responder state lives until the host calls its
//! `end`, which [`Responder`]'s drop does exactly once — also when the task
//! is aborted. Each task holds the loaded library, so the responder code
//! stays mapped while a task can still call it.

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use abi_stable::std_types::{RString, RVec};
use bytes::Bytes;
use futures_core::Stream as _;
use mcpg_plugin_protocol::abi::{
    HTTP_SINK_ACCEPTED, HTTP_SINK_FULL, HttpResponderRef, HttpServerRef,
};
use mcpg_plugin_protocol::transport::{HttpIngressRequestHead, HttpIngressServer};

/// How long a response may wait on a full plugin queue before the host
/// gives up on it.
const STALL_LIMIT: Duration = Duration::from_secs(60);
/// The longest pause between two offers to a full queue.
const MAX_BACKOFF: Duration = Duration::from_millis(50);

/// The host's server state behind one started `http`-wire transport.
pub(crate) struct HttpServerBridge {
    server: Arc<dyn HttpIngressServer>,
    rt: tokio::runtime::Handle,
    next_id: AtomicU64,
    inflight: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    keepalive: Arc<dyn std::any::Any + Send + Sync>,
}

impl HttpServerBridge {
    /// A bridge serving `server` on `rt`. `keepalive` is the loaded library
    /// the plugin's responder callbacks live in.
    pub(crate) fn new(
        server: Arc<dyn HttpIngressServer>,
        rt: tokio::runtime::Handle,
        keepalive: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            server,
            rt,
            next_id: AtomicU64::new(0),
            inflight: Mutex::new(HashMap::new()),
            keepalive,
        })
    }

    /// The FFI server for `start_http`. `owner` is what [`Self::release`]
    /// frees when the transport handle drops.
    pub(crate) fn ffi_ref(owner: *const Arc<Self>) -> HttpServerRef {
        HttpServerRef {
            ctx: owner as usize,
            serve: bridge_serve,
            cancel: bridge_cancel,
        }
    }

    /// Leak one strong reference for the plugin's `ctx`.
    pub(crate) fn into_owner(bridge: Arc<Self>) -> *mut Arc<Self> {
        Box::into_raw(Box::new(bridge))
    }

    /// Stop every response still running and free the plugin's `ctx`.
    ///
    /// # Safety
    /// `owner` comes from [`Self::into_owner`] and the plugin no longer
    /// calls through it (its `transport_handle_drop` returned).
    pub(crate) unsafe fn release(owner: *mut Arc<Self>) {
        // SAFETY: the caller's contract.
        let bridge = unsafe { Box::from_raw(owner) };
        bridge.abort_all();
    }

    fn abort_all(&self) {
        let tasks: Vec<_> = self.lock().drain().map(|(_, task)| task).collect();
        for task in tasks {
            task.abort();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, tokio::task::AbortHandle>> {
        self.inflight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn answer(
        self: Arc<Self>,
        id: u64,
        head: HttpIngressRequestHead,
        body: Bytes,
        mut responder: Responder,
    ) {
        let _done = Untrack {
            bridge: Arc::clone(&self),
            id,
        };
        let outcome = self.deliver(head, body, &responder).await;
        responder.stop(outcome.err().unwrap_or_default());
    }

    /// Run the request and hand its answer to the plugin. `Err` names why
    /// the response stopped early.
    async fn deliver(
        &self,
        head: HttpIngressRequestHead,
        body: Bytes,
        responder: &Responder,
    ) -> Result<(), String> {
        let response = self.server.serve(head, body).await;
        let head_json = serde_json::to_string(&response.head)
            .map_err(|e| format!("response head encode failed: {e}"))?;
        responder
            .offer(|r| (r.head)(r.ctx, RString::from(head_json.as_str())))
            .await?;
        let mut body = response.body;
        while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_next(cx)).await {
            let data = frame?;
            if !data.is_empty() {
                responder
                    .offer(|r| (r.chunk)(r.ctx, RVec::from(data.as_ref())))
                    .await?;
            }
        }
        Ok(())
    }
}

/// Removes a finished response from the in-flight table.
struct Untrack {
    bridge: Arc<HttpServerBridge>,
    id: u64,
}

impl Drop for Untrack {
    fn drop(&mut self) {
        self.bridge.lock().remove(&self.id);
    }
}

/// The plugin's responder for one request. Dropping it calls `end` with
/// `error` (empty: the body is complete).
struct Responder {
    sink: HttpResponderRef,
    error: String,
    /// The library `sink` lives in; dropped only after `end` returned.
    code: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl Responder {
    fn new(sink: HttpResponderRef) -> Self {
        Self {
            sink,
            error: "cancelled".into(),
            code: None,
        }
    }

    /// End the response with `reason` when this responder drops.
    fn stop(&mut self, reason: String) {
        self.error = reason;
    }

    /// Offer one call until the plugin takes it. `Err` names why the
    /// response stops.
    async fn offer(&self, mut call: impl FnMut(&HttpResponderRef) -> u8) -> Result<(), String> {
        let started = Instant::now();
        let mut pause = Duration::from_millis(1);
        loop {
            match call(&self.sink) {
                HTTP_SINK_ACCEPTED => return Ok(()),
                HTTP_SINK_FULL if started.elapsed() < STALL_LIMIT => {
                    tokio::time::sleep(pause).await;
                    pause = (pause * 2).min(MAX_BACKOFF);
                }
                HTTP_SINK_FULL => return Err("the client read nothing for 60 s".into()),
                _ => return Err("the client went away".into()),
            }
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        let error = RString::from(std::mem::take(&mut self.error));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (self.sink.end)(self.sink.ctx, error);
        }));
    }
}

/// # Safety
/// `ctx` is the live `*const Arc<HttpServerBridge>` handed to the plugin.
unsafe fn bridge_of(ctx: usize) -> Arc<HttpServerBridge> {
    // SAFETY: the caller's contract.
    Arc::clone(unsafe { &*(ctx as *const Arc<HttpServerBridge>) })
}

extern "C" fn bridge_serve(
    ctx: usize,
    head_json: RString,
    body: RVec<u8>,
    sink: HttpResponderRef,
) -> u64 {
    let mut responder = Responder::new(sink);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        // SAFETY: the plugin calls `serve` only while its handle is live.
        let bridge = unsafe { bridge_of(ctx) };
        let head = match serde_json::from_str::<HttpIngressRequestHead>(head_json.as_str()) {
            Ok(head) => head,
            Err(e) => {
                responder.stop(format!("the plugin sent an undecodable request head: {e}"));
                return 0;
            }
        };
        let body = Bytes::from(body.into_vec());
        let id = bridge.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let task_bridge = Arc::clone(&bridge);
        responder.code = Some(Arc::clone(&bridge.keepalive));
        // Held across the spawn so the task cannot untrack itself before it
        // is tracked.
        let mut inflight = bridge.lock();
        let task = bridge
            .rt
            .spawn(async move { task_bridge.answer(id, head, body, responder).await });
        inflight.insert(id, task.abort_handle());
        id
    }))
    .unwrap_or(0)
}

extern "C" fn bridge_cancel(ctx: usize, request_id: u64) {
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: the plugin calls `cancel` only while its handle is live.
        let bridge = unsafe { bridge_of(ctx) };
        let task = bridge.lock().remove(&request_id);
        if let Some(task) = task {
            task.abort();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::abi::HTTP_SINK_CLOSED;
    use mcpg_plugin_protocol::transport::{HttpIngressResponse, HttpIngressResponseHead};

    /// Answers every request with a status that echoes the body length and
    /// the given body frames; a `None` frame list keeps the body open.
    struct EchoServer {
        frames: Option<Vec<Result<Bytes, String>>>,
    }

    #[mcpg_plugin_protocol::async_trait]
    impl HttpIngressServer for EchoServer {
        async fn serve(&self, head: HttpIngressRequestHead, body: Bytes) -> HttpIngressResponse {
            let status = 200 + u16::try_from(body.len()).unwrap_or(0);
            let frames: mcpg_plugin_protocol::transport::BoxBodyStream = match &self.frames {
                Some(frames) => Box::pin(futures::stream::iter(frames.clone())),
                None => Box::pin(futures::stream::pending()),
            };
            HttpIngressResponse {
                head: HttpIngressResponseHead {
                    status,
                    headers: vec![("x-uri".to_owned(), head.uri)],
                },
                body: frames,
            }
        }
    }

    /// What the plugin side received, plus how it answers `chunk`.
    #[derive(Default)]
    struct Recorded {
        head: Option<String>,
        chunks: Vec<Vec<u8>>,
        end: Option<String>,
        /// Answers for the next `chunk` calls, front first; empty → ACCEPTED.
        chunk_answers: std::collections::VecDeque<u8>,
    }

    type Rec = Arc<Mutex<Recorded>>;

    extern "C" fn rec_head(ctx: usize, head_json: RString) -> u8 {
        let rec = unsafe { &*(ctx as *const Mutex<Recorded>) };
        rec.lock().unwrap().head = Some(head_json.into_string());
        HTTP_SINK_ACCEPTED
    }

    extern "C" fn rec_chunk(ctx: usize, data: RVec<u8>) -> u8 {
        let rec = unsafe { &*(ctx as *const Mutex<Recorded>) };
        let mut rec = rec.lock().unwrap();
        let answer = rec.chunk_answers.pop_front().unwrap_or(HTTP_SINK_ACCEPTED);
        if answer == HTTP_SINK_ACCEPTED {
            rec.chunks.push(data.into_vec());
        }
        answer
    }

    extern "C" fn rec_end(ctx: usize, error: RString) {
        let rec = unsafe { &*(ctx as *const Mutex<Recorded>) };
        rec.lock().unwrap().end = Some(error.into_string());
    }

    fn sink(rec: &Rec) -> HttpResponderRef {
        HttpResponderRef {
            ctx: Arc::as_ptr(rec) as usize,
            head: rec_head,
            chunk: rec_chunk,
            end: rec_end,
        }
    }

    fn start(server: EchoServer) -> (*mut Arc<HttpServerBridge>, HttpServerRef) {
        let bridge = HttpServerBridge::new(
            Arc::new(server),
            tokio::runtime::Handle::current(),
            Arc::new(()),
        );
        let owner = HttpServerBridge::into_owner(bridge);
        (owner, HttpServerBridge::ffi_ref(owner))
    }

    fn head(uri: &str) -> RString {
        RString::from(
            serde_json::to_string(&HttpIngressRequestHead {
                method: "POST".into(),
                uri: uri.into(),
                ..Default::default()
            })
            .unwrap(),
        )
    }

    async fn wait_for_end(rec: &Rec) -> String {
        for _ in 0..500 {
            if let Some(end) = rec.lock().unwrap().end.clone() {
                return end;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("the host never called end");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_is_answered_with_its_head_then_every_frame_then_a_clean_end() {
        let (owner, server) = start(EchoServer {
            frames: Some(vec![
                Ok(Bytes::from_static(b"a")),
                Ok(Bytes::new()),
                Ok(Bytes::from_static(b"b")),
            ]),
        });
        let rec = Rec::default();
        let id = (server.serve)(
            server.ctx,
            head("/mcp"),
            RVec::from(b"xyz".to_vec()),
            sink(&rec),
        );
        assert_ne!(id, 0);
        assert_eq!(wait_for_end(&rec).await, "");
        let rec = rec.lock().unwrap();
        let got: HttpIngressResponseHead =
            serde_json::from_str(rec.head.as_deref().unwrap()).unwrap();
        assert_eq!(got.status, 203, "the server saw the 3-byte body");
        assert_eq!(got.headers, vec![("x-uri".to_owned(), "/mcp".to_owned())]);
        assert_eq!(
            rec.chunks,
            vec![b"a".to_vec(), b"b".to_vec()],
            "empty frames are skipped"
        );
        unsafe { HttpServerBridge::release(owner) };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_plugin_queue_is_offered_the_same_frame_again() {
        let (owner, server) = start(EchoServer {
            frames: Some(vec![
                Ok(Bytes::from_static(b"one")),
                Ok(Bytes::from_static(b"two")),
            ]),
        });
        let rec = Rec::default();
        rec.lock().unwrap().chunk_answers = [HTTP_SINK_FULL, HTTP_SINK_FULL].into();
        (server.serve)(server.ctx, head("/"), RVec::new(), sink(&rec));
        assert_eq!(wait_for_end(&rec).await, "");
        assert_eq!(
            rec.lock().unwrap().chunks,
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        unsafe { HttpServerBridge::release(owner) };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_closed_client_and_a_failed_body_end_the_response_with_a_reason() {
        let (owner, server) = start(EchoServer {
            frames: Some(vec![
                Ok(Bytes::from_static(b"one")),
                Ok(Bytes::from_static(b"two")),
            ]),
        });
        let closed = Rec::default();
        closed.lock().unwrap().chunk_answers = [HTTP_SINK_CLOSED].into();
        (server.serve)(server.ctx, head("/"), RVec::new(), sink(&closed));
        assert_eq!(wait_for_end(&closed).await, "the client went away");
        assert!(closed.lock().unwrap().chunks.is_empty());
        unsafe { HttpServerBridge::release(owner) };

        let (owner, server) = start(EchoServer {
            frames: Some(vec![
                Ok(Bytes::from_static(b"one")),
                Err("router body failed".into()),
            ]),
        });
        let failed = Rec::default();
        (server.serve)(server.ctx, head("/"), RVec::new(), sink(&failed));
        assert_eq!(wait_for_end(&failed).await, "router body failed");
        assert_eq!(failed.lock().unwrap().chunks, vec![b"one".to_vec()]);
        unsafe { HttpServerBridge::release(owner) };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_and_release_stop_an_open_stream_and_still_call_end() {
        let (owner, server) = start(EchoServer { frames: None });
        let cancelled = Rec::default();
        let id = (server.serve)(server.ctx, head("/sse"), RVec::new(), sink(&cancelled));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            cancelled.lock().unwrap().head.is_some(),
            "the head went out first"
        );
        (server.cancel)(server.ctx, id);
        assert_eq!(wait_for_end(&cancelled).await, "cancelled");
        (server.cancel)(server.ctx, id);
        (server.cancel)(server.ctx, 9999);

        let open = Rec::default();
        (server.serve)(server.ctx, head("/sse"), RVec::new(), sink(&open));
        tokio::time::sleep(Duration::from_millis(20)).await;
        unsafe { HttpServerBridge::release(owner) };
        assert_eq!(wait_for_end(&open).await, "cancelled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undecodable_request_head_is_refused_with_end() {
        let (owner, server) = start(EchoServer {
            frames: Some(Vec::new()),
        });
        let rec = Rec::default();
        let id = (server.serve)(
            server.ctx,
            RString::from("not json"),
            RVec::new(),
            sink(&rec),
        );
        assert_eq!(id, 0);
        let end = rec.lock().unwrap().end.clone().unwrap();
        assert!(
            end.starts_with("the plugin sent an undecodable request head"),
            "{end}"
        );
        assert!(rec.lock().unwrap().head.is_none());
        unsafe { HttpServerBridge::release(owner) };
    }
}
