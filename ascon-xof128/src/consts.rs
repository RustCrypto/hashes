use ascon::State;

const XOF_IV: u64 = 0x0000_0800_00CC_0003;
const CXOF_IV: u64 = 0x0000_0800_00CC_0004;

pub(crate) const XOF_INIT_STATE: State = init_state(XOF_IV);
pub(crate) const CXOF_INIT_STATE: State = init_state(CXOF_IV);

const fn init_state(iv: u64) -> ascon::State {
    let mut state = [iv, 0, 0, 0, 0];
    ascon::permute12(&mut state);
    state
}
