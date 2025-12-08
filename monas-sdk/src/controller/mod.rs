mod keypair;
mod content;
mod share;
mod state;

/// MonasController - SDK のオーケストレーター
/// 
/// 各ドメイン（monas-account, monas-content, monas-state-node）の
/// Presentation層を呼び出してオーケストレーションを行う
pub struct MonasController;

impl MonasController {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MonasController {
    fn default() -> Self {
        Self::new()
    }
}
