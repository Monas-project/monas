/// Auth context used for State Node integration.
///
/// Passes the headers received by the gateway through to the SDK and re-sets them when calling
/// the State Node.
#[derive(Debug, Clone, Default)]
pub struct StateNodeAuthContext {
    pub authorization: Option<String>,
    pub request_signature: Option<String>,
    pub request_timestamp: Option<u64>,
}
