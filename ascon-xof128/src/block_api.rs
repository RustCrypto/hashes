mod cxof;
mod reader;
mod xof;

pub use cxof::AsconCxof128Core;
pub use reader::AsconXofReaderCore;
pub use xof::AsconXof128Core;

const fn init_state(iv: u64) -> ascon::State {
    let mut state = [iv, 0, 0, 0, 0];
    ascon::permute12(&mut state);
    state
}
